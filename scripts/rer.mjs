#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { main } from './base-cli/cli/main.mjs';

if (process.argv[2] === 'recovery') {
 try {
  const { recovery } = await import('./auth-recovery.mjs');
  const result = await recovery(process.argv.slice(3), { root: fileURLToPath(new URL('../', import.meta.url)) });
  console.log(`Recovery token saved to ${result.path}`);
 } catch (error) {
  console.error(error.message);
  process.exitCode = 1;
 }
} else {
 const { localHostArguments } = await import('./installer/auth-host.mjs');
 process.exitCode = await main(await localHostArguments(process.argv.slice(2)));
}
