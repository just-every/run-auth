"""Small process and artifact helpers; all sensitive output stays in evidence files."""
import contextlib, datetime, json, os, time, urllib.request, ssl
from pathlib import Path
from processes import execute
ROOT = Path(__file__).resolve().parents[1]

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')

def command(args, *, env=None, log=None, timeout=None, check=True, console=False, interrupt_grace=120):
    if console and log:
        raise ValueError('console output is only for the nested harness safe progress')
    destination = contextlib.nullcontext(None) if console else open(log or os.devnull, 'ab')
    with destination as output:
        code = execute(args, env=env, output=output, timeout=timeout, interrupt_grace=interrupt_grace)
    if check and code:
        raise RuntimeError(f'{Path(args[0]).name} exited {code}; see {log}')
    return code

def load_versions():
    return dict(line.strip().split('=', 1) for line in (ROOT / 'versions.env').read_text().splitlines() if line and not line.startswith('#'))

def progress_release(versions):
    print('Release: ' + versions['UPSTREAM_TAG'] + ' commit=' + versions['UPSTREAM_COMMIT'], flush=True)
    for key in ('SUITE_IMAGE', 'NGINX_IMAGE', 'MONGO_IMAGE', 'PROVIDER_IMAGE'):
        print('Pinned image: ' + key + '=' + versions[key], flush=True)

def fetch(base, route, *, method='GET', data=None):
    request = urllib.request.Request(base.rstrip('/') + route, data=data, method=method, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=15) as response:
        return response.read()

def wait_suite(base, out, timeout=180):
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            plans = json.loads(fetch(base, '/api/plan/available'))
            if not plans:
                raise ValueError('empty plan list')
            write(out / 'suite-readiness.json', {'ready': True, 'seconds': time.monotonic() - started})
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError('suite_readiness_timeout')

PLANS = {
    'basic': 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]',
    'config': 'oidcc-config-certification-test-plan',
    'logout': 'oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code id_token][client_registration=dynamic_client]',
    'private-jwt': 'oidcc-test-plan[client_auth_type=private_key_jwt][response_type=code][response_mode=default][client_registration=dynamic_client]',
    'basic-static': 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]',
    'private-key-static': 'oidcc-test-plan[client_auth_type=private_key_jwt][response_type=code][response_mode=default][client_registration=static_client]',
}
