import type { AccessRequestsModel } from './pages/access-requests.js'
import type { RetentionModel } from './pages/retention.js'
import type { AccessDecisionsModel } from './pages/access-decisions.js'
import type { AccessReviewsModel } from './pages/access-reviews.js'
export type AuthPage = 'people' | 'move-in' | 'agents' | 'apps' | 'methods' | 'activity' | 'account' | 'organizations' | 'roles' | 'permissions' | 'erasure'

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
  heldVersions?: string[]
  linked_at?: number | string | null
  firstSeen?: boolean
  punycode?: boolean
  replacesClient?: string | null
  keyChanged?: boolean
  replaces?: AppReplacement[]
}

// A client a link takes over from another origin ('moves') or removes at this origin ('identifiers').
export interface AppReplacement {
  name: string
  origin: string
  change: 'moves' | 'identifiers'
}

export interface AuthPasskey {
  id: string
  created_at?: number | string | null
  createdAt?: number | string | null
  last_used_at?: number | string | null
  lastUsedAt?: number | string | null
}

export interface AuthActivity {
  eventId?: string
  actor_id?: string | null
  service_name?: string | null
  service_owner_email?: string | null
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

export interface EnrollmentCampaign {
 id: string; name: string; provider_id: string; current: boolean; cancelled_at: number | null
 starts_at: number; deadline_at: number; cutover_at: number; secondsToCutover: number; remaining: number
 counts: Record<string, number>
 people: Array<{person_id: string; display_name: string; email: string; manager_email: string | null; state: string; factors: string[]; exempt_at: number | null}>
}

export interface DirectorySourceModel {
 sources: Array<{id:string;name:string;kind:string;mode:string;organizationBinding:string;fields:string[];disabled:boolean;lastError:string|null;lastReadAt:number|null}>
 snapshots: Array<{id:string;sourceId:string;state:string;reasons:string[];createdAt:number}>
 preview?: {sourceId:string;snapshotId:string;state:string;digest:string;held:boolean;reasons:string[];refusals:string[];changes:Array<{kind:string;name?:string;groupName?:string;personName?:string;row?:{name?:string;email?:string;active?:boolean;fields?:Record<string,string|null>}}>}
}
export interface FederationModel {
 setups: Array<{id:string;providerId:string;domain:string;state:string;revision:number}>
 previewError?:string
 preview?: {id:string;providerId:string;issuer:string;callback?:string;state:string;revision:number;digest:string;people:Array<{subject:string;email:string;state:string}>}
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
  diagnostic?: {probe?:unknown;affectedApps?:Array<{id:string;name:string}>;worker:string;issue:string;diagnosis:{diagnosis:string;explanation:string;nextAction:string;citations:string[]};repair:{field:string;before:unknown;after:unknown}|null;sources:Array<{id:string;kind:string;observedAt:number;facts:unknown}>;verification:string}

  person?: { email: string; name?: string | null; role?: string; status?: string | null } | null
  after?: string | { id: string; label: string } | null
  activeSessions?: number
  apps?: { name: string; origin: string }[]
  passkey?: boolean
  invitationEmail?: boolean
  domain?: string
  provider?: { id: string; label: string } | null
  people?: { email: string; status: string }[]
  app?: { origin: string; name?: string; firstSeen?: boolean; punycode?: boolean; relinks?: boolean; replaces?: AppReplacement[] } | null
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
  preset: 'google' | 'microsoft' | 'okta' | 'oidc' | 'saml'
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

export interface RerTrustKey {
  kid: string
  source: 'provisioned' | 'owner'
  added_at?: number | null
  withdrawn_at?: number | null
}

export interface DirectoryField { value: string; source: string; also: { source: string; value: string }[] }
export interface DirectoryPerson {
  id: string
  email: string
  name: string
  role: string
  state: 'invited' | 'active' | 'suspended' | 'terminated'
  fields: Record<string, DirectoryField>
  conflicts: { field: string }[]
  groups: { id: string; name: string; via: 'manual' | 'rule'; why?: string[] }[]
  apps: { appId: string; app: string; role: string | null }[]
}
export interface DirectoryAttribute { key: string; label: string; type: string; choices: string[] | null; visibility: string; employeeEditable: boolean; standard: boolean }
export interface DirectoryGroup {
  id: string
  name: string
  rule: { match: 'all' | 'any'; conditions: { field: string; op: string; value?: string; values?: string[] }[] } | null
  owners: { id: string; email: string | null }[]
  apps: { appId: string; app: string; role: string | null }[]
  members: { id: string; email: string | null; via: 'manual' | 'rule'; why?: string[]; matchesRule?: boolean }[]
  excluded: { id: string; email: string | null; reason: string | null }[]
}
export interface DirectoryModel { people: DirectoryPerson[]; groups: DirectoryGroup[]; attributes: DirectoryAttribute[] }

export interface ProfileField { key: string; label: string; type: string; choices: string[] | null; value: string | null; editable: boolean; protectedBy?: string }
export interface ProfileModel {
  person: { id: string; email: string; name: string }
  fields: ProfileField[]
  links: { providerId: string | null; label: string }[]
  providers: { id: string; label: string; linked: boolean }[]
}

export interface DelegatedTask {
  id:string;grantId:string;agentName?:string;personName?:string;personEmail?:string;appName?:string
  organizationId:string;state:string;authorityCurrent:boolean;effectDigest:string;expiresAt:number
  task:{personId:string;purpose:string;audience:string;apiId:string;scopes:string[];appId?:string;role?:string;resourceId?:string;resource?:string;operation?:string;arguments?:Record<string,unknown>;expiresAt:number}
  before:{role:string|null};after:{role:string};requiredApprovals:string[]
  reversalRequest?:{id:string;state:string;createdAt:number}|null;canRequestReversal?:boolean
  revocationReach:{local:string;completedEffect:string;downstream:string}
}

export interface FollowupModel {
 canManage?:boolean;eligibleAdmins?:Array<{id:string;email:string;name:string}>
 obligationsPage?: {hasMore:boolean;nextCursor:string|null};historyPage?: {hasMore:boolean;nextCursor:string|null}
 policy: {enabled:boolean;calendar:{timezone:string;weekdays:number[];holidays:string[];at:string};reminderBusinessDays:number;deadlineBusinessDays:number;recipients:string[];escalationRecipients:string[];escalation:string}
 obligations: Array<{id:string;kind:string;source_id:string;case_id?:string|null;canSend?:boolean;person_id:string|null;owner_id:string|null;next_action:string;calendar:string;deadline_at:number;next_due_at:number;state:string;last_error:string|null;delivery_error:string|null;reminders_stopped_at:number|null}>
 history: Array<{obligation_id:string;event:string;created_at:number;error:string|null}>
 limitations:string[]
}

export interface AuthPageModel {
  onboarding?: Array<{person_id:string; start_local:string; time_zone:string; lead_days:number; personal_verified_at:number|null; rescinded_at:number|null; contact_authority:string|null; recovery_notices_enabled:number; temporaryPassRequired:boolean}>
  automations?: import('./pages/automations.js').AutomationsModel
  retention?: RetentionModel
  requests?: AccessRequestsModel
  decisions?: AccessDecisionsModel
  reviews?: AccessReviewsModel

  followup?: FollowupModel
  delegations?: {organizationId:string;targetApi:string;grants:DelegatedTask[];agents:Array<{id:string;clientId:string;name:string;state:string;expiresAt:number}>;hasMore:boolean;nextCursor:string|null}
  delegation?: DelegatedTask & {canConsent:boolean;canApprove:boolean}
  delegationApps?: Array<{id:string;name:string}>
  roles?: { canDesignRoles:boolean; rank:number; permissions:Record<string,string>; roles:Array<{id:string;name:string;rank:number;permissions:string[]}>; ownGrants:Array<{id:string;roleId:string;permissions:string[]}>; grants:Array<{id:string;person_id:string;role_id:string;active:boolean}>; groups:Array<{id:string;name:string}>; apps:Array<{id:string;name:string}>; cases:Array<{id:string;person_id:string;state:string}> }
  temporaryPasses?: {people:Array<{personId:string;email:string;name:string;canRequest:boolean;canIssue:boolean}>,requests:Array<{id:string;personId:string;createdAt:number;issuedAt:number|null}>,passes:Array<{id:string;personId:string;expiresAt:number;revokedAt:number|null;completedAt:number|null}>}
  recoveryCases?: {cases:Array<{id:string;personId:string;email:string;state:string;canAttest:boolean;canReset:boolean;canClose:boolean}>}
  rolePeople?: Array<{id:string;email:string;name:string;canResetFactors:boolean}>
  roleError?: string
  refresh?: {admin:boolean;canManage:boolean;clients:Array<{clientId:string;name:string}>;apis:Array<{id:string;appId:string;name:string;audience:string}>;profiles:Array<{clientId:string;name:string;enabled:number;idleMs:number;absoluteMs:number}>;consent:null|{id:string;appName:string;deviceName:string;audience:string;scopes:string[];identityScopes:string[];idleMs:number;absoluteMs:number};grants:Array<{id:string;personId:string;personEmail:string;appName:string;clientId:string;deviceName:string;scopes:string[];audience:string;createdAt:number;lastUsedAt:number;idleExpiresAt:number;absoluteExpiresAt:number;revokedAt:number|null;reason:string|null;status:string}>}
  resourceApis?: {apis:Array<{id:string;appId:string;name:string;audience:string;scopes:string[];roles:unknown[];resources:unknown[]}>;services:Array<{id:string;clientId:string;name:string;ownerId:string;purpose:string;scopes:string[];revokedAt:number|null}>}
  erasure?: {policy:unknown;holds:unknown[];receipts:Array<Record<string,unknown>>}
  organizations?: { current: {id:string;name:string}; memberships: Array<{id:string;name:string;role:string;path:string;active:boolean}>; canCreate:boolean }

  adminServices?: AdminService[];
  adminServiceCustody?: {scopes:string[]};
  profile?: ProfileModel
  directory?: DirectoryModel
  page: AuthPage | string
  issuer?: string
  returnTo?: string
  user?: AuthUser | null
  me?: AuthUser | null
  isAdmin: boolean
  localEmailConfirmed?: boolean
  people?: AuthPerson[]
  domains?: AuthDomain[]
  abuse?: {policy:{sourceLimit:number;aggregateLimit:number;cooldownSeconds:number};refusals:Array<{created_at:number;detail:string}>}
  delivery?: import('./pages/delivery.js').DeliveryModel
  notifications?: import('./pages/notifications.js').NotificationsModel
  domainOwnership?: { id: string; domain: string; label: string; value: string; expiresAt: number; status: string; people: { id: string; email: string; role: string }[] }[]
  domainRules?: { domain: string; provider_id: string; available: boolean }[]
  policyProviders?: { id: string; label: string }[]
  apps?: AuthApp[]
  rerTrust?: RerTrustKey[]
  pendingApps?: AuthApp[]
  methods?: AuthPasskey[]
  passkeys?: AuthPasskey[]
  canReadAudit?: boolean
  activityError?: {status: number;message: string;filters: Record<string,string>}
  activityPage?: {events: AuthActivity[];total: number;asOf: number;limit: number;nextCursor: string | null;filters: {from: number;to: number;person: string;event: string}}
  activity?: AuthActivity[]
  notices?: AuthNotice[]
  recoveries?: AuthRecovery[]
  notice?: string | { message?: string } | null
  csrf?: string
  unavailableActions?: string[]
  providers?: AuthProvider[]
  moveIn?: { batches: MoveInBatch[]; batch: MoveInBatch | null; rows: MoveInRow[]; directorySources?: DirectorySourceModel; federation?: FederationModel | null; campaigns?: EnrollmentCampaign[]; campaignProviders?: Array<{id: string; label: string; preset: string}>; campaignManagers?: Array<{id: string; email: string; display_name: string}> }
  agents?: { apps?:Array<{id:string;name:string;protocol:string}>;people?:Array<{id:string;email:string}>;now?: number; keys: AgentKey[]; proposals: AgentProposal[]; proposal: AgentProposal | null }
  inlineHooks?: { points: string[]; hooks: { id: string; point: string; url: string; appId: string | null; clientId: string | null; allowedFields: string[]; timeoutMs: number; failClosed: boolean; status: string }[] }
  workforce?: WorkforceModel
  events?: { types: string[]; subscriptions: Array<{ id: string; url: string; types: string[]; createdAt: number; status: string; deliveries: Record<string, number> }> }
  launcher?: LauncherApp[]
}

export interface LauncherApp { id: string; name: string; launch: string | null; kind: string; state: string; role?: string | null; icon?: string; availableFrom?: number | null; favorite: boolean; lastUsedAt: number | null; requestable?: boolean }
export interface CompanyAppObligation {
  subject_type: string; subject_id: string; label?: string | null; reason: string; operation?: string | null; state: string
  event_at: number; dispatched_at?: number | null; verified_at?: number | null; attempts: number; last_status?: number | null; last_error?: string | null; overdue?: boolean
}
export interface CompanyApp {
  mapping: { version: number; versions: { version: number; program: string; created_at: number }[] }
  id: string; name: string; protocol: string; recipe?: string | null
  oidc: { clientId: string; authMethod: string; redirectUris: string[]; postLogoutRedirectUris: string[]; requirePkce: boolean; subjectType: string; legacyFlows: boolean; frontchannelLogoutUri?: string | null; backchannelLogoutUri?: string | null; idTokenAlg: string; liveSecrets: number; previousSecretUntil?: number | null } | null; entityId: string; acs: Array<{ url: string; binding: string }>; slo?: { url: string; binding: string } | null
  nameIdFormat: string; sign: string; digest: string; encryption?: string | null; idpInitiated: boolean; version: number; status: string
  assignments: Array<{ type: string; id: string; label?: string | null; role?: string | null }>
  provisioning: { baseUrl: string; deprovision: string; groups: boolean; lastSuccessAt?: number | null; lastError?: string | null; lastReconciledAt?: number | null } | null
  obligations: CompanyAppObligation[]
}
export interface CatalogRecipe {
  id: string; name: string; protocols: string[]; inputs: Array<{ name: string; label: string; example?: string; kind?: string }>
  provisioning: { kind: string; api: string; credential?: string | null; groups: boolean; status?: string | null }
  edition: string; permissions: string; roles: string; attributes: string; testUser: string; rotation: string; limits: string; verifiedAt: number | null; verification: string
}
export interface WorkforceModel {
  bookmarks?: Array<{id:string;name:string;url:string;icon:string;group_name:string}>
  idp: { entityId: string; metadataUrl: string; ssoUrl: string; sloUrl: string }
  samlKeys: Array<{ kid: string; state: string; createdAt: number; activatedAt?: number | null }>
  companyApps: CompanyApp[]
  groups: Array<{ id: string; name: string; members: Array<{ id: string; email: string }> }>
  catalog: CatalogRecipe[]
  nameIdFormats: string[]
  oidcMethods: string[]
}

export interface SignInPageModel {
  issuer?: string
  returnTo?: string
  notice?: string | null
  csrf?: string
  providers?: AuthProvider[]
}

export interface AdminService { id:string;clientId:string;name:string;purpose:string;ownerId:string;ownerEmail:string|null;ownerName:string|null;jwks:{keys:Array<{kid?:string;alg?:string;kty:string}>};scopes:string[];resources:Record<'people'|'groups'|'apps',string[]>;allowedIps:string[];revision:number;createdAt:number;expiresAt:number;revokedAt:number|null;suspendedAt:number|null;lastUsedAt:number|null;suspensionReason:string|null;status:'active'|'suspended'|'expired'|'revoked' }
