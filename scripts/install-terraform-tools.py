#!/usr/bin/env python3
"""Install checksum-verified Terraform and OpenTofu CLIs for provider journeys."""
import hashlib
import io
import platform
from pathlib import Path
import sys
import urllib.request
import zipfile

output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
system = platform.system().lower()
arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
for name, version, base in [
    ('terraform', '1.13.3', 'https://releases.hashicorp.com/terraform/1.13.3/'),
    ('tofu', '1.10.6', 'https://github.com/opentofu/opentofu/releases/download/v1.10.6/'),
]:
    filename = f'{name}_{version}_{system}_{arch}.zip'
    data = urllib.request.urlopen(base + filename, timeout=90).read()
    sums = urllib.request.urlopen(base + f'{name}_{version}_SHA256SUMS', timeout=90).read().decode()
    expected = next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*') == filename)
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit(f'{name}: checksum mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        target = output / name
        target.write_bytes(archive.read(name))
        target.chmod(0o755)
    print(f'{name} {version}: verified and installed')
