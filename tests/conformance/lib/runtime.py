import os, subprocess, time
from common import ROOT, command, write, now
from docker_connection import connect, isolated_environment
from processes import finish_cleanup

class Runtime:
    def __init__(self, temp, out, versions, target, extra_hosts=None):
        self.out, self.temp, self.target = out, temp, target
        self.env, self.plugins = isolated_environment(temp, versions)
        default_host = 'localhost.emobix.co.uk' if target == 'reference' else 'localhost'
        self.env.setdefault('BASE_URL', 'https://' + default_host + ':8443')
        self.env.setdefault('BASE_MTLS_URL', 'https://' + default_host + ':8444')
        self.project = 'oidcc-' + temp.name.lower().replace('_', '-')
        write(out / 'runtime.json', {'project': self.project, 'target': target, 'created_at': now(), 'suite_origins': {key: {'value': self.env[key], 'source': 'caller' if key in os.environ else 'target_default'} for key in ('BASE_URL', 'BASE_MTLS_URL')}})
        self.compose = ['docker', 'compose', '-p', self.project, '-f', str(ROOT / 'compose.yml')]
        if target == 'reference':
            self.compose += ['--profile', 'reference']
            reference_alias = temp / 'reference-alias.json'
            write(reference_alias, {'services': {'nginx': {'networks': {'default': {'aliases': ['oidcc-provider', 'localhost.emobix.co.uk']}}}}})
            self.compose += ['-f', str(reference_alias)]
        if os.environ.get('REFERENCE_NETWORK'):
            override = temp / 'network.json'
            write(override, {'services': {'nginx': {'networks': {'reference': {}}}}, 'networks': {'reference': {'external': True, 'name': os.environ['REFERENCE_NETWORK']}}})
            self.compose += ['-f', str(override)]
        if extra_hosts:
            host_override = temp / 'extra-hosts.json'
            # Docker rejects add-host on containers using another container's
            # network namespace. Configure its owner, whose hosts file is shared.
            write(host_override, {'services': {'nginx': {'extra_hosts': extra_hosts}}})
            self.compose += ['-f', str(host_override)]
        self.started = False
        self.new_images = []
        self.image_keys = ['SUITE_IMAGE', 'NGINX_IMAGE', 'MONGO_IMAGE'] + (['PROVIDER_IMAGE'] if target == 'reference' else [])

    def cmd(self, args, name='docker.log', **kwargs):
        return command(args, env=self.env, log=self.out / name, **kwargs)

    def snapshot(self, when):
        for label, args in [('containers', ['ps', '-a', '--no-trunc']), ('volumes', ['volume', 'ls']), ('images', ['image', 'ls', '--digests', '--no-trunc']), ('disk', ['system', 'df']), ('owned-containers', ['ps', '-a', '--filter', 'label=com.docker.compose.project=' + self.project]), ('owned-volumes', ['volume', 'ls', '--filter', 'label=com.docker.compose.project=' + self.project]), ('owned-networks', ['network', 'ls', '--filter', 'label=com.docker.compose.project=' + self.project])]:
            self.cmd(['docker'] + args, f'{when}-{label}.txt', check=False, timeout=30)

    def start(self):
        connect(self.env, self.out, self.project, self.plugins)
        self.snapshot('before')
        for key, image in ((k, self.env[k]) for k in self.image_keys):
            if self.cmd(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], 'image-presence.log', check=False) != 0:
                self.new_images.append(image)
        self.started = True  # down also runs after a partial pull/up failure
        self.cmd(self.compose + ['pull'], timeout=600)
        if self.target == 'reference':
            self.mount_provider_files()
        self.provider_started = time.monotonic()
        self.cmd(self.compose + ['up', '-d', '--pull', 'never'], timeout=120)
        self.cmd(self.compose + ['images', '--format', 'json'], 'image-footprint.json', check=False)
        for image in [self.env[k] for k in self.image_keys]:
            self.cmd(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}} {{.Size}}', image], 'image-bytes.txt', check=False)

    def mount_provider_files(self):
        # The sample provider reads config.json, server.key and server.crt from
        # its image's working directory; mount upstream's local files there.
        workdir = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Config.WorkingDir}}', self.env['PROVIDER_IMAGE']],
                                 env=self.env, capture_output=True, text=True, timeout=30, check=True).stdout.strip()
        if not workdir.startswith('/'):
            raise RuntimeError('provider_image_working_directory_unknown')
        source = self.env['UPSTREAM_DIR'] + '/.gitlab-ci/'
        files = {'local-provider-oidcc.json': 'config.json', 'local-provider.key': 'server.key', 'local-provider-oidcc.crt': 'server.crt'}
        override = self.temp / 'provider-mounts.json'
        write(override, {'services': {'oidcc-provider': {'volumes': [f'{source}{name}:{workdir}/{target}:ro' for name, target in files.items()]}}})
        self.compose += ['-f', str(override)]

    def wait_provider(self, service='oidcc-provider'):
        started = self.provider_started
        probe = "require('https').get('https://oidcc-provider:3000/.well-known/openid-configuration',{rejectUnauthorized:false},r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>{try{let d=JSON.parse(b);process.exit(r.statusCode===200&&d.issuer&&d.authorization_endpoint?0:1)}catch(e){process.exit(1)}})}).on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),2500)"
        while time.monotonic() - started < 120:
            try:
                code = self.cmd(self.compose + ['exec', '-T', service, 'node', '-e', probe], 'provider-readiness.log', timeout=min(4, 120 - (time.monotonic() - started)), check=False)
                if code == 0:
                    write(self.out / 'provider-readiness.json', {'ready': True, 'seconds': time.monotonic() - started, 'bound_seconds': 120, 'at': now()})
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(min(1, max(0, 120 - (time.monotonic() - started))))
        write(self.out / 'provider-readiness.json', {'ready': False, 'seconds': time.monotonic() - started, 'bound_seconds': 120, 'at': now()})
        raise RuntimeError('provider_discovery_timeout_120_seconds')

    def close(self):
        with finish_cleanup():
            self._close()

    def _close(self):
        errors = []
        def attempt(args, name, timeout=30):
            try:
                rc = self.cmd(args, name, check=False, timeout=timeout)
                if rc:
                    errors.append(name + ':exit_' + str(rc))
                return rc
            except Exception as exc:
                errors.append(name + ':' + type(exc).__name__)
                return -1
        if self.started:
            attempt(self.compose + ['logs', '--no-color'], 'compose.log')
            rc = attempt(self.compose + ['down', '-v', '--remove-orphans'], 'cleanup.log', 120)
            # No force/prune: shared or in-use images are retained and reported.
            for image in self.new_images:
                attempt(['docker', 'image', 'rm', image], 'image-cleanup.log', 90)
        else:
            rc = 0
        try:
            self.snapshot('after')
        except Exception as exc:
            errors.append('after_snapshot:' + type(exc).__name__)
        remaining = {}
        for kind, args in [('containers', ['ps', '-aq']), ('volumes', ['volume', 'ls', '-q']), ('networks', ['network', 'ls', '-q'])]:
            try:
                result = subprocess.run(['docker'] + args + ['--filter', 'label=com.docker.compose.project=' + self.project], env=self.env, capture_output=True, text=True, timeout=15, check=True)
                remaining[kind] = result.stdout.splitlines()
            except Exception as exc:
                remaining[kind] = ['unverified:' + type(exc).__name__]
        write(self.out / 'cleanup.json', {'compose_down_exit': rc, 'project': self.project, 'errors': errors, 'remaining_owned_resources': remaining})
        if rc or errors or any(remaining.values()):
            raise RuntimeError('compose_cleanup_failed_or_owned_resources_remain')
