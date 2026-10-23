import {readFile} from 'node:fs/promises';
import {importPKCS8} from 'jose';
import {createAdminClient} from '@runeditrun/auth-sdk/admin';

// Run only on your server; the file remains in the operator's private custody.
const privateKey = await importPKCS8(await readFile(process.env.AUTH_PRIVATE_KEY_FILE, 'utf8'), 'ES256');
const client = createAdminClient({issuer: process.env.AUTH_ISSUER, clientId: process.env.AUTH_CLIENT_ID,
  privateKey, kid: process.env.AUTH_KEY_ID, scopes: ['groups.read']});
try {
  for await (const {data} of client.pages('/groups')) console.log(JSON.stringify(data.items));
} catch (error) {
  console.error(JSON.stringify({error: error.code ?? 'configuration_failed', status: error.status}));
  process.exitCode = 1;
}
