import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {Readable} from 'node:stream';
import {createBrowserApp} from './browser.mjs';

// Run unchanged from the installed package; configuration contains public registrations only.
const config = JSON.parse(await readFile(process.env.AUTH_APP_CONFIG, 'utf8'));
const app = createBrowserApp(config);
const address = new URL(config.origin);
const server = createServer(async (incoming, outgoing) => {
  try {
    const request = new Request(new URL(incoming.url, config.origin), {
      method: incoming.method, headers: incoming.headers,
      ...(!['GET', 'HEAD'].includes(incoming.method) ? {body: Readable.toWeb(incoming), duplex: 'half'} : {}),
    });
    const response = await app.fetch(request);
    outgoing.writeHead(response.status, {...Object.fromEntries(response.headers), 'set-cookie': response.headers.getSetCookie()});
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch { outgoing.writeHead(503, {'content-type':'application/json'}); outgoing.end('{"error":"application_unavailable"}'); }
});
server.listen(Number(config.listenPort ?? (address.port || 3000)), '127.0.0.1', () => console.log('Documents quickstart ready'));
const stop = () => {server.closeAllConnections(); server.close();};
process.on('SIGTERM', stop); process.on('SIGINT', stop);
