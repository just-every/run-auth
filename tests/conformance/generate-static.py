#!/usr/bin/env python3
"""Generate fresh ES256 fixtures with OpenSSL; private key material is never printed."""
import argparse, base64, json, os, subprocess, tempfile
from pathlib import Path

def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')

def tlv(data, at=0):
    tag, size, pos = data[at], data[at + 1], at + 2
    if size > 127:
        count = size & 127
        size = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    return tag, data[pos:pos + size], pos + size

def generate():
    with tempfile.TemporaryDirectory(prefix='oidcc-es256-') as scratch:
        pem = Path(scratch) / 'key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(pem)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = subprocess.check_output(['openssl', 'ec', '-in', str(pem), '-outform', 'DER'], stderr=subprocess.DEVNULL)
        _, sequence, _ = tlv(der)
        _, _, next_field = tlv(sequence)
        tag, scalar, _ = tlv(sequence, next_field)
        assert tag == 4 and len(scalar) == 32
        public = subprocess.check_output(['openssl', 'pkey', '-in', str(pem), '-pubout', '-outform', 'DER'], stderr=subprocess.DEVNULL)[-65:]
        assert public[0] == 4
    jwk = {'kty': 'EC', 'crv': 'P-256', 'use': 'sig', 'alg': 'ES256', 'kid': b64(os.urandom(12)), 'x': b64(public[1:33]), 'y': b64(public[33:])}
    return jwk, dict(jwk, d=b64(scalar))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--issuer', required=True)
    parser.add_argument('--base-url', default='https://localhost:8443')
    parser.add_argument('--alias', default='auth-static-es256')
    parser.add_argument('--browser-config', type=Path, help='Existing suite config whose browser and override fields are copied')
    args = parser.parse_args()
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=False)
    config = json.loads((Path(__file__).parent / 'external-auth.example.json').read_text())
    config.update(alias=args.alias, description='Static ES256 private_key_jwt clients; register both clients and replace their IDs before use', server={'discoveryUrl': args.issuer.rstrip('/') + '/.well-known/openid-configuration'})
    if args.browser_config:
        original = json.loads(args.browser_config.read_text())
        for key in ['browser', 'override']:
            if key in original:
                config[key] = original[key]
    for key in ['client', 'client2']:
        public, private = generate()
        config[key]['jwks'] = {'keys': [private]}
        registration = {'client_name': 'Conformance ' + key, 'redirect_uris': [args.base_url.rstrip('/') + '/test/a/' + args.alias + '/callback'], 'grant_types': ['authorization_code'], 'response_types': ['code'], 'token_endpoint_auth_method': 'private_key_jwt', 'token_endpoint_auth_signing_alg': 'ES256', 'id_token_signed_response_alg': 'ES256', 'jwks': {'keys': [public]}}
        (args.out / (key + '-registration.json')).write_text(json.dumps(registration, indent=2) + '\n')
    private_config = args.out / 'config.json'
    private_config.write_text(json.dumps(config, indent=2) + '\n')
    private_config.chmod(0o600)
    print('Created private mode-0600 static configuration and two public registration payloads in ' + str(args.out), flush=True)
