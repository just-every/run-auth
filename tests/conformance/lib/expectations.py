"""Scope unchanged expectation entries using the suite's resolved plan metadata."""
import fnmatch
import hashlib
import json
import re
from urllib.parse import urlencode
from urllib.error import HTTPError
from common import fetch, write


def effective_modules(detail):
    # TestRunner merges the stored plan variant over each module row's fixed
    # variant. TestPlanApi has already filled unset defaults and filtered rows.
    return [{'testModule': row['testModule'], 'variant': {**(row.get('variant') or {}), **(detail.get('variant') or {})}}
            for row in detail['modules']]


def select_entries(entries, modules, config_filename):
    selected, decisions = [], []
    for index, entry in enumerate(entries):
        candidates = [row for row in modules if fnmatch.fnmatch(row['testModule'], entry['test-name'])]
        expected_variant = entry['variant']
        if expected_variant != '*' and not isinstance(expected_variant, dict):
            raise ValueError('invalid_expected_variant')
        matches = [row for row in candidates if expected_variant == '*' or all(
            key in row['variant'] and row['variant'][key] == value for key, value in expected_variant.items())]
        config_matches = fnmatch.fnmatch(config_filename, entry['configuration-filename'])
        included = bool(matches) and config_matches
        if included:
            selected.append(entry)  # Never edit a condition, block, variant or comment.
        decisions.append({'source_index': index, 'selected': included,
                          'reason': 'applicable' if included else 'module_not_in_plan' if not candidates else 'configuration_not_matched' if not config_matches else 'variant_not_matched',
                          'matching_modules': matches if config_matches else []})
    return selected, decisions


def scope_plan(base, spec, config_filename, directory, failures, skips):
    name = spec.split('[')[0]
    pairs = re.findall(r'\[([a-z_]+)=([^\]]+)\]', spec)
    if len(dict(pairs)) != len(pairs):
        raise ValueError('duplicate_plan_variant')
    query = urlencode({'planName': name, 'variant': json.dumps(dict(pairs))})
    receipt = {'spec': spec, 'metadata_source': 'POST /api/plan, GET /api/plan/{id}, GET /api/runner/available',
               'metadata_plan_id': None, 'metadata_plan_deleted': False, 'modules': [], 'files': {}}
    audit = directory / 'expectation-selection.json'
    write(audit, receipt)
    # Empty configuration creates only a plan record, never a module or provider
    # request. Unlike plan/info, creation resolves conditional rows and defaults.
    try:
        created = json.loads(fetch(base, '/api/plan?' + query, method='POST', data=b'{}'))
    except HTTPError as error:
        receipt['creation_response'] = {'http_status': error.code, 'body': error.read().decode('utf-8', errors='replace')}
        write(audit, receipt)
        raise
    ident = created['id']
    if not re.fullmatch(r'[\w-]+', ident):
        raise ValueError('invalid_metadata_plan_id')
    receipt['metadata_plan_id'] = ident
    try:
        detail = json.loads(fetch(base, '/api/plan/' + ident))
        if detail['planName'] != name or detail['_id'] != ident or not detail['modules']:
            raise ValueError('invalid_resolved_plan_metadata')
        modules = effective_modules(detail)
        # Accept canonical public variant values, never guess what a synthetic
        # "default" alias means. ResponseMode's genuine "default" is canonical.
        catalog = {row['testName']: row['variants'] for row in json.loads(fetch(base, '/api/runner/available'))}
        allowed = {}
        for row in modules:
            for key, metadata in catalog[row['testModule']].items():
                allowed.setdefault(key, set()).update(metadata['variantValues'])
        for row in modules:
            for key, value in row['variant'].items():
                if value not in allowed.get(key, set()):
                    raise ValueError('noncanonical_variant_value:' + key)
        receipt.update(modules=modules, resolved_plan_variant=detail.get('variant') or {})
        paths = []
        for kind, source in [('failures', failures), ('skips', skips)]:
            entries = json.loads(source.read_text())
            if not isinstance(entries, list):
                raise ValueError('expectations_must_be_array')
            selected, decisions = select_entries(entries, modules, config_filename)
            dest = directory / ('expected-' + kind + '.json')
            write(dest, selected)
            paths.append(dest)
            receipt['files'][kind] = {'source_file': '../expected-' + kind + '.json',
                                      'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                                      'selected_file': dest.name, 'decisions': decisions}
        return paths
    finally:
        write(audit, receipt)
        fetch(base, '/api/plan/' + ident, method='DELETE')
        receipt['metadata_plan_deleted'] = True
        write(audit, receipt)
