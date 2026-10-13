"""Discover Docker without reading an existing credential/configuration file."""
import os
import subprocess
from pathlib import Path
from common import command, now, write

DESKTOP_PLUGINS = Path('/Applications/Docker.app/Contents/Resources/cli-plugins')
# Docker Desktop's per-user socket, read from the invoking user's real home
# before HOME is replaced for the isolated configuration.
DESKTOP_USER_SOCKET = 'unix://' + str(Path.home() / '.docker/run/docker.sock')


def isolated_environment(temp, versions):
    env = os.environ.copy()
    original_plugins = Path.home() / '.docker/cli-plugins'
    isolated = temp / 'home'
    config = isolated / '.docker'
    config.mkdir(parents=True)
    plugins = []
    for directory in (original_plugins, DESKTOP_PLUGINS):
        compose = directory / 'docker-compose'
        if compose.is_file() and os.access(compose, os.X_OK):
            plugins.append(str(directory))
    if str(original_plugins) in plugins:
        (config / 'cli-plugins').symlink_to(original_plugins)
    # Docker still searches its normal system-wide plugin directories. This
    # fresh file adds Desktop's verified executable even under remote-run HOME.
    write(config / 'config.json', {'cliPluginsExtraDirs': plugins})
    env.pop('DOCKER_CONTEXT', None)  # no contexts are imported into the fresh config
    env.update(versions, HOME=str(isolated), DOCKER_CONFIG=str(config), UPSTREAM_DIR=str(temp / 'upstream'))
    return env, plugins


def connect(env, out, project, plugins):
    receipt = {'at': now(), 'project': project, 'cli_plugins_extra_dirs': plugins, 'attempts': [], 'selected': None}
    supplied = bool(env.get('DOCKER_HOST'))
    choices = [('explicit_DOCKER_HOST' if supplied else 'docker_default', None)]
    if not supplied:
        choices.append(('desktop_user_socket', DESKTOP_USER_SOCKET))
    for name, host in choices:
        if receipt['selected'] is not None:
            continue
        if host:
            env['DOCKER_HOST'] = host
        try:
            code = command(['docker', 'info', '--format', '{{.ServerVersion}}'], env=env, log=out / 'docker-connection.log', timeout=20, check=False)
        except subprocess.TimeoutExpired:
            code = 124
        receipt['attempts'].append({'connection': name, 'exit': code})
        if code == 0:
            receipt['selected'] = name
    write(out / 'docker-connection.json', receipt)
    if receipt['selected'] is None:
        raise RuntimeError('docker_daemon_unreachable')
    print('Docker connection: ' + receipt['selected'], flush=True)
    receipt['compose_exit'] = command(['docker', 'compose', 'version', '--short'], env=env, log=out / 'docker-compose-version.txt', timeout=20, check=False)
    write(out / 'docker-connection.json', receipt)
    if receipt['compose_exit']:
        raise RuntimeError('docker_compose_unavailable')
