import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { docsSite } from './scripts/site-docs/plugin.mjs'

// The run site's build (rer build --site, src/site/pages.tsx): the docs module and
// React only. Never the app's vite.config.ts, whose Worker and Start plugins do not run in Node.
export default defineConfig({ plugins: [docsSite(), react()] })
