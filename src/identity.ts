import { checkIdentity, type EditionIdentity } from './base/identity'
import branding from './branding.json'

// What the installed instance's Lobby (Base's shared installed homepage at /) shows,
// and the run site (run-auth.com, src/site) reads.
export const identity: EditionIdentity = checkIdentity({
 product: 'Auth',
 deployment: branding.name,
 purpose: '{deployment}: one sign-in for the apps your team uses.',
 tagline: 'Owner-run sign-in for your apps: email links, passkeys and sign-out everywhere.',
 signInPath: '/signin',
 runSite: 'https://run-auth.com',
 installedHome: 'lobby',
 theme: '/rer-theme.css',
 mark: '/brand/mark.svg',
 band: '/brand/band.svg',
 fonts: '/fonts/fonts.css',
 accentColor: branding.primaryColor,
})
