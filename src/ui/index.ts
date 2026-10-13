import type { AuthPage, AuthPageModel, SignInPageModel } from './model.js'
import { pageCopy, renderShell } from './shell.js'
import { renderPeoplePage } from './pages/people.js'
import { renderMoveInPage } from './pages/move-in.js'
import { renderAgentsPage } from './pages/agents.js'
import { renderAppsPage } from './pages/apps.js'
import { renderMethodsPage } from './pages/methods.js'
import { renderActivityPage } from './pages/activity.js'
import { renderAccountPage } from './pages/account.js'
import { renderSignInPage } from './pages/signin.js'

export { renderSignInPage }
export type { AuthPage, AuthPageModel, SignInPageModel } from './model.js'

const pageRenderers: Record<AuthPage, (model: AuthPageModel) => string> = {
  people: renderPeoplePage,
  'move-in': renderMoveInPage,
  agents: renderAgentsPage,
  apps: renderAppsPage,
  methods: renderMethodsPage,
  activity: renderActivityPage,
  account: renderAccountPage,
}

export function renderAuthPage(model: AuthPageModel): string {
  const user = model.user ?? model.me ?? null
  if (!user) return renderSignInPage({
    issuer: model.issuer,
    returnTo: model.returnTo,
    notice: typeof model.notice === 'string' ? model.notice : undefined,
    csrf: model.csrf,
  })
  const page = Object.hasOwn(pageCopy, model.page) ? model.page as AuthPage : 'account'
  return renderShell(model, page, pageRenderers[page](model))
}
