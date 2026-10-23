# Auth SFTP ingress

See [the HR file feed guide](../../docs/hr-file-feeds.md) for private configuration,
key binding, host verification and the reviewed lifecycle profile. Run on Node
22.20+ with `npm install --prefix connectors/sftp`, then
`node connectors/sftp/serve.mjs`. The service defaults to loopback and exposes
SFTP upload only; configuration and private host-key paths are supplied through
`AUTH_SFTP_FEEDS_FILE` and `AUTH_SFTP_HOST_KEY_FILE`.
