"""Preserve each plan and its genuine JSON/log ZIP even after runner failures."""
import json, re, zipfile
from common import fetch, write

def list_plans(base):
    plans, start = [], 0
    while True:
        page = json.loads(fetch(base, f'/api/plan?length=1000&start={start}'))
        rows = page['data']
        plans.extend(rows)
        if len(rows) < 1000:
            return plans
        start += 1000

def collect(base, directory, excluded):
    errors, collected = [], []
    try:
        plans = list_plans(base)
    except Exception as exc:
        return [], ['plan_list_unavailable: ' + type(exc).__name__]
    for plan in plans:
        ident = str(plan.get('id', plan.get('_id', '')))
        if ident in excluded:
            continue
        if not re.fullmatch(r'[\w-]+', ident):
            errors.append('invalid_plan_id')
            continue
        try:
            detail = json.loads(fetch(base, '/api/plan/' + ident))
            write(directory / (ident + '.plan.json'), detail)
            archive = directory / (ident + '.zip')
            archive.write_bytes(fetch(base, '/api/plan/export/' + ident))
            with zipfile.ZipFile(archive) as zipped:
                assert zipped.testzip() is None
                assert any(n.endswith('.json') for n in zipped.namelist())
            collected.append(ident)
        except Exception as exc:
            errors.append('plan_export_unavailable:' + ident + ':' + type(exc).__name__)
    return collected, errors
