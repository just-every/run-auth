// Every string on the run site's homepage, exactly as the approved spec gives it
// (rer-consolidation evidence/gr-auth-style/SPEC.md §1). Since the owner's 28 Oct
// decision "free" is a footnote (the closing line), never the hero, a lead or a section.

export const hero = {
  title: ['Sign in', 'with a touch.'],
  sub: 'Passkeys and email links for your team, and one sign-in across the apps you link.',
  alternativeTo: ['Auth0', 'Okta', 'Microsoft Entra'],
  figure: 'Auth hero: invite a person, continue with a passkey, signed in to two apps',
}

export const closing = {
  title: 'Welcome everyone in.',
  body: 'Run Auth on your own computer, register a passkey and link your first app.',
  licence: 'Free and open source, MIT licensed.',
}

export interface Feature { id: string; eyebrow: string; title: string; body: string; side: 'left' | 'right' }
export const features: Feature[] = [
  { id: 'passkeys', eyebrow: 'Passkeys', title: 'Passkeys for everyone.', body: 'Each person confirms their email once, then registers a passkey. Administrators always sign in with one.', side: 'left' },
  { id: 'apps', eyebrow: 'Your apps', title: 'One sign-in for your apps.', body: 'Approve an app and your team signs in to it with Auth. Sign out everywhere reaches every app you linked.', side: 'right' },
  { id: 'people', eyebrow: 'People', title: 'Everyone in one place.', body: "Invite people, allow your company's domain and suspend access from one list.", side: 'left' },
  { id: 'move-in', eyebrow: 'Move in', title: 'Bring your team across.', body: 'Stage a user export from Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud, review it, then admit people as invitations.', side: 'right' },
  { id: 'open-source', eyebrow: 'Open source', title: 'Open source.', body: 'MIT licensed. Read, change and run every line of the source.', side: 'left' },
  { id: 'ownership', eyebrow: 'Ownership', title: 'Yours, start to finish.', body: 'Run Auth on your own computer. Your people, passkeys and apps stay in your installation, and export with you.', side: 'right' },
]

export const details = {
  eyebrow: 'Also included',
  title: 'The quiet details.',
  tiles: [
    { icon: 'user', label: 'Passkey recovery', line: 'Another administrator approves, or a notified 72-hour delay passes.' },
    { icon: 'refresh', label: 'Sign out everywhere', line: 'End every session in every linked app.' },
    { icon: 'list', label: 'Activity', line: 'Every account and issuer event, recorded.' },
    { icon: 'sliders', label: 'Required providers', line: 'Require Google, Microsoft or Okta for a domain.' },
    { icon: 'spark', label: 'Agent proposals', line: 'An agent prepares a change; a person approves it with a passkey.' },
    { icon: 'swap', label: 'Export and import', line: 'People, apps and a signed grant map move with you.' },
  ],
} as const

export const footer = { line: 'Owner-run sign-in for your apps.' }
export const pageTitle = 'Auth — Sign in with a touch'
