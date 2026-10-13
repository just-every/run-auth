#!/usr/bin/env python3
"""Summarize exported facts, applying the pinned runner's expectation semantics."""
import copy, importlib.util, json, sys
from collections import Counter
from pathlib import Path
from common import write
from exports import read_exports, reconcile_plan, validate_logs
STATUSES = ['PASSED', 'WARNING', 'SKIPPED', 'REVIEW', 'FAILED', 'INTERRUPTED']

def summarize(out, upstream, failures, skips):
    sys.path.insert(0, str(upstream / 'scripts'))
    spec = importlib.util.spec_from_file_location('pinned_runner', upstream / 'scripts/run-test-plan.py')
    runner = importlib.util.module_from_spec(spec)
    stdout = sys.stdout
    try:
        spec.loader.exec_module(runner)
    finally:
        sys.stdout = stdout
    return summarize_run(out, runner, failures, skips)


def summarize_run(out, runner, failures, skips):
    """Apply the pinned analyzer to genuine exported records."""
    run = json.loads((out / 'run.json').read_text())
    total = Counter({s: 0 for s in STATUSES})
    for plan in run['plans']:
        folder = out / plan['folder']
        counts, modules, unexpected = Counter({s: 0 for s in STATUSES}), [], list(plan.get('errors', []))
        infos, export_errors = read_exports(folder)
        expected_count, plan_errors = reconcile_plan(folder, plan, infos)
        unexpected += export_errors + plan_errors
        complete = not unexpected
        for ident, record in sorted(infos.items()):
            info, logs = record['testInfo'], record['results']
            status = info.get('result') or 'INTERRUPTED'
            if status not in STATUSES:
                status = 'INTERRUPTED'
            counts[status] += 1
            # The upstream runner accepts FINISHED and INTERRUPTED as terminal;
            # configure-time failures use INTERRUPTED with an actual FAILED result.
            terminal = info.get('status') in ['FINISHED', 'INTERRUPTED']
            complete = complete and terminal and status != 'INTERRUPTED'
            analysis_counts = dict.fromkeys(['EXPECTED_FAILURES', 'UNEXPECTED_FAILURES', 'EXPECTED_FAILURES_NOT_HAPPEN', 'EXPECTED_WARNINGS', 'UNEXPECTED_WARNINGS', 'EXPECTED_WARNINGS_NOT_HAPPEN', 'EXPECTED_SKIPS', 'UNEXPECTED_SKIPS', 'EXPECTED_SKIPS_NOT_HAPPEN'], 0)
            causes = []
            try:
                validate_logs(logs)
            except (KeyError, ValueError) as exc:
                causes.append('invalid_module_logs:' + type(exc).__name__)
                complete = False
                logs = []
            analysis = runner.analyze_result_logs(ident, info['testName'], info.get('variant', {}), status, {'config_file': plan['config_filename']}, logs, copy.deepcopy(failures), copy.deepcopy(skips), analysis_counts)
            for key in ['unexpected_failures', 'unexpected_warnings', 'expected_failures_did_not_happen', 'expected_warnings_did_not_happen']:
                causes += [key + ':' + event['src'] + ':' + event['current_block'] for event in analysis[key]]
            for key in ['unexpected_skip', 'expected_skip_did_not_happen']:
                if analysis[key]:
                    causes.append(key)
            if status == 'INTERRUPTED':
                causes.append('module_result_' + status)
            if not terminal:
                causes.append('nonterminal_module_status:' + str(info.get('status')))
            if status == 'WARNING' and not analysis['expected_warnings'] and not causes:
                causes.append('warning_without_warning_log')
            if status == 'FAILED' and not analysis['expected_failures'] and not analysis['expected_skip'] and not causes:
                causes.append('failed_without_failure_log')
            unexpected += [info['testName'] + ':' + cause for cause in causes]
            review_conditions = sorted({log['src'] for log in logs if log.get('result') == 'REVIEW'})
            modules.append({'id': ident, 'name': info['testName'], 'variant': info.get('variant', {}), 'status': status, 'suite_result': info.get('result'), 'suite_status': info.get('status'), 'manual_review_conditions': review_conditions, 'unexpected_causes': causes, 'expectations': analysis})
        if plan.get('runner_exit') != 0:
            unexpected.append('runner_exit_' + str(plan.get('runner_exit', 'not_started')))
        plan.update(counts=dict(counts), expected_module_count=expected_count, exported_module_count=len(infos), modules=modules, run_complete=complete, all_modules_passed=complete and counts['PASSED'] == expected_count, unexpected_causes=sorted(set(unexpected)))
        total.update(counts)
        write(folder / 'summary.json', plan)
    run['counts'] = dict(total)
    run['unexpected_causes'] = run.get('errors', []) + [p['folder'] + ':' + cause for p in run['plans'] for cause in p['unexpected_causes']]
    if not run['plans']:
        run['unexpected_causes'].append('no_plans_executed')
    run['passed'] = not run['unexpected_causes']
    run['run_complete'] = bool(run['plans']) and not run.get('errors') and all(p['run_complete'] for p in run['plans'])
    run['all_modules_passed'] = run['run_complete'] and all(p['all_modules_passed'] for p in run['plans'])
    write(out / 'summary.json', run)
    def markdown(plans):
        lines = ['| Plan | ' + ' | '.join(STATUSES) + ' | Unexpected |', '|---|' + '---:|' * 7]
        for p in plans:
            lines.append('| ' + p['spec'] + ' | ' + ' | '.join(str(p['counts'][s]) for s in STATUSES) + ' | ' + str(len(p['unexpected_causes'])) + ' |')
        for p in plans:
            lines += ['', 'Plan: `' + p['spec'] + '`', '', 'Run complete: ' + str(p['run_complete']) + '; all modules PASSED: ' + str(p['all_modules_passed']), '', '| Module | Result | Expected conditions | Manual review conditions |', '|---|---|---|---|']
            for m in p['modules']:
                expected = m['expectations']['expected_failures'] + m['expectations']['expected_warnings']
                labels = [e['src'] for e in expected]
                if m['expectations']['expected_skip']:
                    labels.append('expected skip')
                lines.append('| ' + m['name'] + ' | ' + m['status'] + ' | ' + ', '.join(labels) + ' | ' + ', '.join(m['manual_review_conditions']) + ' |')
            lines.extend('\n- Unexpected: ' + c for c in p['unexpected_causes'])
        return '\n'.join(lines) + '\n'
    for p in run['plans']:
        p['expected_counts'] = {'failure': sum(len(m['expectations']['expected_failures']) for m in p['modules']), 'warning': sum(len(m['expectations']['expected_warnings']) for m in p['modules']), 'skip': sum(bool(m['expectations']['expected_skip']) for m in p['modules'])}
        write(out / p['folder'] / 'summary.json', p)
        (out / p['folder'] / 'summary.md').write_text(markdown([p]))
    write(out / 'summary.json', run)
    pins = '\n'.join('- ' + key + ': `' + value + '`' for key, value in run['pins'].items())
    (out / 'summary.md').write_text('Harness acceptance: **' + ('PASS' if run['passed'] else 'FAIL') + '**\n\nRun complete: ' + str(run['run_complete']) + '; all modules PASSED: ' + str(run['all_modules_passed']) + '. Acceptance follows the pinned runner; it is not certification. REVIEW results require the listed manual checks.\n\nIssuer: ' + str(run.get('issuer')) + '\n\nStart: ' + run['started_at'] + '\n\nEnd: ' + str(run.get('ended_at')) + '\n\n' + pins + '\n\n' + markdown(run['plans']) + '\n' + '\n'.join(run.get('errors', [])))
    return run['passed']

if __name__ == '__main__':
    out, upstream, failfile, skipfile = map(Path, sys.argv[1:])
    raise SystemExit(0 if summarize(out, upstream, json.loads(failfile.read_text()), json.loads(skipfile.read_text())) else 1)
