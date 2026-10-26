export interface FederationProviderConfig {
 id:string; label?:string; preset:'oidc'|'saml'; issuer:string; subjectEmails:Record<string,string>;
 clientId?:string; clientSecret?:string; privateKey?:JsonWebKey; tokenAuthMethod?:'private_key_jwt'|'client_secret_basic'|'client_secret_post';
 endpointPins?:{authorization:string;token:string;jwks:string}; certificates?:string[]; ssoUrl?:string; entityId?:string; nameIdFormat?:string; signAuthnRequests?:boolean;
}
export interface AuthRuntimeOptions {
 db: D1Database; origin: string; organizationId?: string; secret: string; local?: boolean; now?: () => number;
 mailEventInstallationId?: string; mailProvider?: string; sendgridWebhookKey?: string;
 mail?: (message: {to: string; subject: string; text: string; html: string; deliveryId: string; customArgs?: Record<string,string>}, store?: {db:D1Database;organizationId:string}) => Promise<unknown>;
 waitUntil?: (work: Promise<unknown>) => void;
 upstreamProviders?: Array<import('../modules/operator-auth/index.mjs').IdentityProviderConfig|FederationProviderConfig>;
 upstreamFetch?: typeof fetch;
 /** Outbound requests to linked apps (pull, callback, logout); defaults to fetch. */
 linkFetch?: typeof fetch;
 /** Outbound requests to provisioning connectors (SCIM); defaults to fetch. */
 connectorFetch?: typeof fetch;
 notificationSlackWebhook?: string;
 notificationFetch?: typeof fetch;
 dnsFetch?: typeof fetch;
 agentModelKey?: string;
 agentModelWorkspace?: string;
 agentModelFetch?: typeof fetch;
 /** RER Managed: JSON object of trusted link-approval public keys (kid -> JWK). */
 rerTrustKeys?: string;
 allowDevSession?: (request: Request) => boolean | Promise<boolean>;
}
export interface AuthRuntime { context: AuthRuntimeOptions & {now: () => number}; fetch(request:Request):Promise<Response|null>; upstreamProviders():Promise<any[]>; model(request:Request,page?:string):Promise<any> }
export function createAuthRuntime(options:AuthRuntimeOptions):AuthRuntime;
export function stageSigningKey(context:AuthRuntime['context'],algorithm?:'ES256'|'RS256'):Promise<{kid:string;useAfter:number}>;
export function retireSigningKey(context:AuthRuntime['context'],kid:string):Promise<void>;
export function installRecoveryToken(db:D1Database,token:string,now?:number):Promise<void>;

export function ensureSigningKey(context:AuthRuntime['context']):Promise<{kid:string;useAfter:number}|null>;

export function maintainAuth(context:AuthRuntime['context']):Promise<void>;
