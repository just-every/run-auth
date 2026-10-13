"""Read the pinned suite's signed module exports without exposing configuration."""
import json
import zipfile
from collections import Counter


def read_exports(folder):
    records, errors = {}, []
    for archive in sorted(folder.glob('*.zip')):
        try:
            with zipfile.ZipFile(archive) as zipped:
                names = [name for name in zipped.namelist() if name.endswith('.json')]
                if not names:
                    raise ValueError('no_module_json')
                for name in names:
                    try:
                        record = json.loads(zipped.read(name))
                        info, logs = record['testInfo'], record['results']
                        ident = info['_id']
                        if not isinstance(ident, str) or not ident or info['testId'] != ident:
                            raise ValueError('inconsistent_module_identity')
                        if not isinstance(info['testName'], str) or not isinstance(info['variant'], dict):
                            raise ValueError('invalid_module_metadata')
                        if not isinstance(logs, list) or not logs or not all(isinstance(log, dict) for log in logs):
                            raise ValueError('missing_module_logs')
                        if name.removesuffix('.json') + '.sig' not in zipped.namelist():
                            raise ValueError('missing_module_signature')
                        # Export timestamps and private config are not result facts.
                        public_info = {key: info.get(key) for key in ('_id', 'testName', 'variant', 'planId', 'status', 'result')}
                        fact = {'testInfo': public_info, 'results': logs}
                        if ident in records and records[ident] != fact:
                            errors.append('conflicting_module_exports:' + ident)
                        else:
                            records[ident] = fact
                    except Exception as exc:
                        errors.append('invalid_module_export:' + archive.name + ':' + name + ':' + type(exc).__name__)
        except Exception as exc:
            errors.append('invalid_export:' + archive.name + ':' + type(exc).__name__)
    return records, errors


def reconcile_plan(folder, plan, records):
    """LogApi exports the last instance of every Plan.Module, not old attempts."""
    errors, expected = [], {}
    if len(plan.get('plan_ids', [])) != 1:
        errors.append('expected_one_created_plan')
    expected_count = 0
    for ident in plan.get('plan_ids', []):
        try:
            detail = json.loads((folder / (ident + '.plan.json')).read_text())
            if detail['_id'] != ident or detail['planName'] != plan['spec'].split('[')[0]:
                raise ValueError('plan_identity_mismatch')
            for module in detail['modules']:
                expected_count += 1
                instances = module.get('instances') or []
                if not instances or instances[-1] not in records:
                    errors.append('missing_module_export:' + module['testModule'])
                    continue
                latest = instances[-1]
                if latest in expected:
                    errors.append('duplicate_module_instance:' + latest)
                expected[latest] = module['testModule']
                info = records[latest]['testInfo']
                if info['testName'] != module['testModule'] or info['planId'] != ident:
                    errors.append('module_identity_mismatch:' + latest)
        except Exception as exc:
            errors.append('invalid_plan_export:' + ident + ':' + type(exc).__name__)
    if not records or not expected_count:
        errors.append('missing_plan_or_module_evidence')
    errors.extend('unexpected_module_export:' + ident for ident in records.keys() - expected.keys())
    selection = folder / 'expectation-selection.json'
    if selection.exists():
        try:
            audit = json.loads(selection.read_text())
            if not audit['metadata_plan_deleted']:
                errors.append('metadata_plan_not_deleted')
            planned = Counter((row['testModule'], json.dumps(row['variant'], sort_keys=True)) for row in audit['modules'])
            actual = Counter((row['testInfo']['testName'], json.dumps(row['testInfo']['variant'], sort_keys=True)) for row in records.values())
            if planned != actual:
                errors.append('resolved_module_metadata_mismatch')
        except Exception as exc:
            errors.append('invalid_expectation_selection:' + type(exc).__name__)
    return expected_count, errors


def validate_logs(logs):
    blocks = set()
    for log in logs:
        if log.get('startBlock') is True and log.get('src') == '-START-BLOCK-':
            blocks.add(log['blockId'])
        elif 'result' in log:
            if not isinstance(log.get('src'), str):
                raise ValueError('missing_condition_name')
            if 'blockId' in log and log['blockId'] not in blocks:
                raise ValueError('missing_log_block')
