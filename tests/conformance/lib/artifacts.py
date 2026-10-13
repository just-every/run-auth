"""Keep restricted evidence outside a successful remote-run checkout."""
import tarfile
from pathlib import Path


def preserve_runner_artifact(out):
    cwd = Path.cwd().resolve()
    for parent in [cwd, *cwd.parents]:
        if parent.name != 'repo' or parent.parent.parent.name != 'jobs':
            continue
        logs = parent.parent.parent.parent / 'logs'
        if not logs.is_dir():
            continue
        archive = logs / ('oidc-conformance-' + parent.parent.name + '-' + out.name + '.tar.gz')
        partial = archive.with_suffix(archive.suffix + '.partial')
        with tarfile.open(partial, 'w:gz') as bundle:
            bundle.add(out, arcname=out.name)
        partial.chmod(0o600)
        partial.replace(archive)
        print('Evidence archive: ' + str(archive), flush=True)
        return archive
