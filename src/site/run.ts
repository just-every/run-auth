import type { RunData } from '../base/run-site'
import pkg from '../../package.json'

/** Every string and command on the run site's Run page (/run). */
export const run: RunData = {
  name: 'Auth',
  repository: pkg.repository,
  clone: 'npx -y @runeditrun/rer dev just-every/run-auth',
  folder: 'run-auth',
  requirements: 'Runs on macOS, Linux or Windows with WSL2, with git. The installer brings Node when it is missing, and rer brings pnpm.',
  licence: 'MIT',
  docs: true,
  hosted: [],
}
