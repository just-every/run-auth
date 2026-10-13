import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { operatorInstaller, developmentTarget, previewTarget } from '../base-onboarding/operator-installer.mjs';
import { selectLocalState } from '../base-onboarding/local/state.mjs';
import { commandAdapter as createCommandAdapter } from '../base-cli/cli/adapter.mjs';
import { ownerDeploy } from '../base-cli/cli/deploy.mjs';
import { localInstaller } from '../base-onboarding/adapter.mjs';
import { RerError } from '../base-cli/cli/errors.mjs';
import { browserInstaller, browserSignIn } from './auth-signin.mjs';
import * as model from './ui/seed.mjs';

export { selectLocalState };
const foundation = operatorInstaller({
 database: 'auth', features: model.features,
 async prepare({ root, input, store }) {
  // export and import run prepare without answers; the saved branding stays.
  if (input.APP_NAME === undefined && input.PRIMARY_COLOR === undefined) return;
  await store.step('Saving application branding');
  await writeFile(join(root, 'src/branding.json'), JSON.stringify({ name: input.APP_NAME, primaryColor: input.PRIMARY_COLOR }, null, 2) + '\n');
 },
});
const lifecycle = { ...foundation, ...localInstaller({ ...foundation.hooks, signIn: browserSignIn }), install: browserInstaller(foundation.install) };
// Append newly declared managed secrets on setup reruns; the shared writer
// preserves existing generated values and unchanged settings bytes.
lifecycle.settings.keepExisting = false;
lifecycle.supplied = ['AUTH_ENCRYPTION_KEY'];
lifecycle.settings.supplied = lifecycle.supplied;
const localSettings = lifecycle.settings.values;
lifecycle.settings.values = context => ({ ...localSettings(context), AUTH_ENCRYPTION_KEY: randomBytes(32).toString('base64url') });
export const adapter = lifecycle;
export const { install } = lifecycle;
export const commandAdapter = createCommandAdapter(lifecycle, {
 dev: developmentTarget, preview: previewTarget, verify: ['pnpm', ['run', 'verify:app']], deploy: ownerDeploy('deploy.json', lifecycle),
 portability: { export: refuseTransfer, import: refuseTransfer },
 setup: { manifestFile: 'rer-setup.json' }, browserModule: 'scripts/installer/ui/seed.mjs',
 // Local dev identity: the local-only Worker entry, the build output rer build
 // scans for the dev layer, and the kept end-to-end email-link test.
 devIdentity: { entry: 'src/server.dev.ts', output: ['dist'], emailLinkTest: 'tests/email-link.mjs' },
 localOnlyKeys: ['RER_DEV_ORIGIN', 'RER_DEV_IDENTITY'],
 product: model.product.name, input: { names: { email: 'OWNER_EMAIL', name: 'displayName' }, async defaults(root) { const { readFile } = await import('node:fs/promises'); const branding = JSON.parse(await readFile(join(root, 'src/branding.json'), 'utf8')); return { APP_NAME: branding.name, PRIMARY_COLOR: branding.primaryColor }; } },
});

function refuseTransfer() {
 throw new RerError('auth_transfer_pending', 'Auth export and import await the merged Base linking and signed grant-map support. Generic archives would expose sessions and signing keys and cannot safely restore identities.', 1);
}
