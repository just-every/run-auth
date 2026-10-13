export type AuthPage = 'people' | 'move-in' | 'agents' | 'apps' | 'methods' | 'activity' | 'account'

export interface AuthUser {
  id: string
  name?: string | null
  email: string
  role?: string
  amr?: string[]
  admin?: boolean
  method?: string
}

export interface AuthPerson {
  id: string
  name?: string | null
  email: string
  role?: string
  status?: string
  created_at?: number | string | null
  createdAt?: number | string | null
}

export interface AuthDomain {
  domain: string
  created_at?: number | string | null
  createdAt?: number | string | null
}

export interface AuthApp {
  id: string
  name?: string | null
  origin: string
  source?: string | null
  created_at?: number | string | null
  createdAt?: number | string | null
  disabled_at?: number | string | null
  disabledAt?: number | string | null
  status?: string
  versions?: string[]
}

export interface AuthPasskey {
  id: string
  created_at?: number | string | null
  createdAt?: number | string | null
  last_used_at?: number | string | null
  lastUsedAt?: number | string | null
}

export interface AuthActivity {
  id?: string | number
  actor_email?: string | null
  actorEmail?: string | null
  event: string
  subject_id?: string | null
  subjectId?: string | null
  created_at?: number | string | null
  createdAt?: number | string | null
  detail?: string | null
}

export interface MoveInBatch {
  id: string
  source_system: string
  format?: string
  file_name: string
  export_date: string
  row_count?: number
  admitted?: number
  created_at?: number | null
  undone_at?: number | null
  undo_report?: { removed: string[]; kept: { email: string; reasons: string[] }[] } | null
  former_subjects?: number
}

export interface MoveInRow {
  idx: number
  sourceId: string | null
  email: string | null
  displayName: string | null
  disabled: boolean | null
  groups: string[]
  status: 'staged' | 'admitted' | 'undone'
  invitedAt: number | null
  reasons: string[]
  admittable: boolean
  selected: boolean
}

export interface AgentKey {
  id: string
  label: string
  owner_email: string
  created_at: number
  expires_at: number
  last_used_at: number | null
  renewed_at: number | null
  revoked_at: number | null
  revoked_by_email: string | null
  ended_reason: 'owner_suspended' | 'owner_demoted' | 'owner_changed' | null
}

export interface AgentEffect {
  person?: { email: string; name?: string | null; role?: string; status?: string | null } | null
  after?: string | { id: string; label: string } | null
  activeSessions?: number
  apps?: { name: string; origin: string }[]
  passkey?: boolean
  invitationEmail?: boolean
  domain?: string
  provider?: { id: string; label: string } | null
  people?: { email: string; status: string }[]
}

export interface AgentProposal {
  id: string
  kind: string
  reason: string
  effect: AgentEffect
  fresh?: AgentEffect
  unchanged?: boolean
  changed?: string[]
  created_at: number
  expires_at: number
  status: 'pending' | 'expired' | 'done' | 'rejected' | 'failed'
  outcome: { reason?: string; changed?: string[] } | null
  decided_at: number | null
  decided_by_email: string | null
  key_label: string
  key_revoked_at: number | null
  key_ended_reason: AgentKey['ended_reason']
  key_owner_email: string
}

export interface AuthNotice {
  id?: string
  message: string
  created_at?: number | string | null
  createdAt?: number | string | null
}

export interface AuthProvider {
  id: string
  label: string
  preset: 'google' | 'microsoft' | 'okta'
  startPath: string
  authorizationOrigins: string[]
  visible: boolean
}

export interface AuthRecovery {
  id: string
  person_id?: string
  personId?: string
  email?: string
  created_at?: number | string | null
  createdAt?: number | string | null
  ready_at?: number | string | null
  readyAt?: number | string | null
  approved_by?: string | null
  approvedBy?: string | null
}

export interface AuthPageModel {
  page: AuthPage | string
  issuer?: string
  returnTo?: string
  user?: AuthUser | null
  me?: AuthUser | null
  isAdmin: boolean
  localEmailConfirmed?: boolean
  people?: AuthPerson[]
  domains?: AuthDomain[]
  domainRules?: { domain: string; provider_id: string; available: boolean }[]
  policyProviders?: { id: string; label: string }[]
  apps?: AuthApp[]
  pendingApps?: AuthApp[]
  methods?: AuthPasskey[]
  passkeys?: AuthPasskey[]
  activity?: AuthActivity[]
  notices?: AuthNotice[]
  recoveries?: AuthRecovery[]
  notice?: string | { message?: string } | null
  csrf?: string
  unavailableActions?: string[]
  providers?: AuthProvider[]
  moveIn?: { batches: MoveInBatch[]; batch: MoveInBatch | null; rows: MoveInRow[] }
  agents?: { now?: number; keys: AgentKey[]; proposals: AgentProposal[]; proposal: AgentProposal | null }
}

export interface SignInPageModel {
  issuer?: string
  returnTo?: string
  notice?: string | null
  csrf?: string
  providers?: AuthProvider[]
}
