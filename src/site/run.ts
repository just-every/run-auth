import type { RunData } from '../base/run-site'
import pkg from '../../package.json'

/** Every string and command on the run site's Run page (/run). */
export const run: RunData = {
  name: 'Auth',
  repository: pkg.repository,
  clone: 'npx -y @runeditrun/rer dev just-every/run-auth',
  folder: 'run-auth',
  requirements: 'Needs Node 22 or later and pnpm 10.12.4, on macOS, Linux or Windows with WSL2.',
  licence: 'MIT',
  docs: true,
  hosted: [],
}
