#!/usr/bin/env python3
"""Run unchanged pinned upstream plans; always export and tear down owned resources."""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from common import ROOT, PLANS, command, fetch, load_versions, now, progress_release, wait_suite, write
from artifacts import preserve_runner_artifact
from collect import collect, list_plans
from expectations import scope_plan
from processes import RunInterrupted, finish_cleanup, install_signal_handlers
from runtime import Runtime

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', choices=['reference', 'external'], required=True)
    parser.add_argument('--plans', default='basic,config,logout,private-key')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--extra-host', action='append', default=[], metavar='NAME=ADDRESS', help='Add host mappings on nginx, the shared network namespace owner; ADDRESS may be host-gateway')
    parser.add_argument('--expected-failures', type=Path, help='Owner-approved upstream-format expectations, external only')
    args = parser.parse_args()
    if args.target == 'external' and not args.config:
        parser.error('--config is required for external')
    if args.target == 'reference' and (args.config or args.expected_failures):
        parser.error('reference uses only the pinned upstream local configuration and expectations')
    if not all(re.fullmatch(r'[a-zA-Z0-9.-]+=(?:host-gateway|[a-fA-F0-9:.]+)', host) for host in args.extra_host):
        parser.error('--extra-host must be NAME=IP or NAME=host-gateway')
    args.specs = [PLANS.get(p.strip().lower(), p.strip()) for p in args.plans.split(',')]
    if not all(re.fullmatch(r'oidcc-[a-z0-9-]+(?:\[[a-z_]+=[a-zA-Z0-9_ -]+\])*', p) for p in args.specs):
        parser.error('use aliases or exact full plan specs, without module selection')
    return args

def main():
    args = parse()
    os.umask(0o077)
    if hasattr(os, 'nice'):
        os.nice(15)
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit('--out must be empty or absent')
    out.mkdir(parents=True, exist_ok=True)
    versions = load_versions()
    progress_release(versions)
    run = {'target': args.target, 'started_at': now(), 'ended_at': None, 'issuer': None, 'pins': versions, 'plans': [], 'errors': []}
    for i, spec in enumerate(args.specs, 1):
        folder = f'{i:02d}-' + spec.split('[')[0]
        (out / folder).mkdir()
        run['plans'].append({'spec': spec, 'folder': folder, 'runner_exit': None, 'plan_ids': [], 'errors': [], 'config_filename': ''})
    write(out / 'run.json', run)
    install_signal_handlers()
    passed = False
    with tempfile.TemporaryDirectory(prefix='oidcc-') as scratch:
        temp = Path(scratch)
        runtime = Runtime(temp, out, versions, args.target, args.extra_host)
        upstream, python = temp / 'upstream', temp / 'venv/bin/python'
        failures, skips = temp / 'expected-failures.json', temp / 'expected-skips.json'
        write(failures, [])
        write(skips, [])
        try:
            command(['git', 'clone', '--depth', '1', '--branch', versions['UPSTREAM_TAG'], 'https://gitlab.com/openid/conformance-suite.git', str(upstream)], log=out / 'source.log', timeout=180)
            actual = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
            if actual != versions['UPSTREAM_COMMIT']:
                raise RuntimeError('upstream_tag_commit_mismatch')
            (out / 'upstream-commit.txt').write_text(actual + '\n')
            command([sys.executable, '-m', 'venv', str(temp / 'venv')], log=out / 'dependencies.log', timeout=120)
            command([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', '-r', str(upstream / 'scripts/requirements.txt')], log=out / 'dependencies.log', timeout=180)
            source = upstream / '.gitlab-ci/local-provider-oidcc-conformance-config.json' if args.target == 'reference' else args.config.resolve()
            config = temp / source.name
            shutil.copyfile(source, config)
            parsed = json.loads(config.read_text())
            discovery = parsed.get('server', {}).get('discoveryUrl', '')
            run['issuer'] = parsed.get('server', {}).get('issuer') or discovery.removesuffix('/.well-known/openid-configuration')
            if not parsed.get('server'):
                raise RuntimeError('server_configuration_required')
            if args.target == 'reference':
                shutil.copyfile(upstream / '.gitlab-ci/expected-failures-local.json', failures)
                shutil.copyfile(upstream / '.gitlab-ci/expected-skips-local.json', skips)
            elif args.expected_failures:
                shutil.copyfile(args.expected_failures.resolve(), failures)
            # Receipts contain approved expectation conditions, never client private configuration.
            shutil.copyfile(failures, out / 'expected-failures.json')
            shutil.copyfile(skips, out / 'expected-skips.json')
            runtime.start()
            if args.target == 'reference':
                runtime.wait_provider()
            base = runtime.env['BASE_URL'].rstrip('/')
            wait_suite(base, out)
            write(out / 'suite-available-plans.json', json.loads(fetch(base, '/api/plan/available')))
            env = runtime.env.copy()
            env.update(CONFORMANCE_SERVER=base + '/', CONFORMANCE_SERVER_MTLS=runtime.env['BASE_MTLS_URL'].rstrip('/') + '/', CONFORMANCE_DEV_MODE='1', PYTHONUNBUFFERED='1')
            for plan in run['plans']:
                plan.update(started_at=now(), config_filename=str(config))
                print('Plan start: ' + plan['spec'] + ' at=' + plan['started_at'], flush=True)
                directory = out / plan['folder']
                seen = None
                deadline = time.monotonic() + 1800
                try:
                    if args.target == 'external' and not args.expected_failures:
                        # Inventory and the genuine configured runner are distinct
                        # observations. Preserve inventory errors and still obtain
                        # the native runner's real full-configuration outcome.
                        plan_failures, plan_skips = failures, skips
                        try:
                            plan_failures, plan_skips = scope_plan(base, plan['spec'], str(config), directory, failures, skips)
                        except Exception as exc:
                            plan['errors'].append('metadata_inventory_error:' + type(exc).__name__)
                    else:
                        plan_failures, plan_skips = scope_plan(base, plan['spec'], str(config), directory, failures, skips)
                    seen = {str(p.get('id', p.get('_id'))) for p in list_plans(base)}
                    plan['runner_exit'] = command([str(python), str(upstream / 'scripts/run-test-plan.py'), '--no-parallel', '--export-dir', str(directory), '--expected-failures-file', str(plan_failures), '--expected-skips-file', str(plan_skips), plan['spec'], str(config)], env=env, log=directory / 'runner.log', timeout=max(0, deadline - time.monotonic()), check=False)
                except subprocess.TimeoutExpired:
                    plan['runner_exit'] = 124
                    plan['errors'].append('plan_timeout_1800_seconds')
                except RunInterrupted as exc:
                    plan['runner_exit'] = exc.child_returncode
                    raise
                except Exception as exc:
                    plan['errors'].append('plan_setup_or_run_error:' + type(exc).__name__)
                finally:
                    with finish_cleanup():
                        if seen is not None:
                            plan['plan_ids'], errors = collect(base, directory, seen)
                            plan['errors'].extend(errors)
                        plan['ended_at'] = now()
                        write(out / 'run.json', run)
                        print('Plan end: ' + plan['spec'] + ' runner_exit=' + str(plan['runner_exit']) + ' at=' + plan['ended_at'], flush=True)
        except BaseException as exc:
            run['errors'].append(type(exc).__name__ + ':' + str(exc))
        finally:
            with finish_cleanup():
                try:
                    runtime.close()
                except BaseException as exc:
                    run['errors'].append('cleanup_error:' + type(exc).__name__ + ':' + str(exc))
                run['ended_at'] = now()
                write(out / 'run.json', run)
                if python.exists() and (upstream / 'scripts/run-test-plan.py').exists():
                    try:
                        passed = command([str(python), str(ROOT / 'lib/summarize.py'), str(out), str(upstream), str(failures), str(skips)], log=out / 'summary.log', timeout=120, check=False) == 0
                    except Exception as exc:
                        run['errors'].append('summary_error:' + type(exc).__name__)
                        write(out / 'run.json', run)
                if not (out / 'summary.json').exists():
                    run.update(passed=False, counts=dict.fromkeys(['PASSED', 'WARNING', 'SKIPPED', 'REVIEW', 'FAILED', 'INTERRUPTED'], 0), unexpected_causes=run['errors'] + ['summary_unavailable'])
                    write(out / 'summary.json', run)
                    (out / 'summary.md').write_text('FAIL: ' + '\n'.join(run['unexpected_causes']) + '\n')
                preserve_runner_artifact(out)
    print(('PASS' if passed else 'FAIL') + ': ' + str(out / 'summary.json'), flush=True)
    return 0 if passed else 1

if __name__ == '__main__':
    raise SystemExit(main())
