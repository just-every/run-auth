import type {AuthRuntime} from './index.mjs';
type Context=AuthRuntime['context'];
export interface AuthSession { id:string;person_id:string;person_version:number;amr:string;created_at:number;expires_at:number;revoked_at:number|null;email:string;display_name:string;upstream_proof_id:string|null;local_email_verified_at:number|null;role:'owner'|'admin'|'member' }
export function session(ctx:Context,request:Request):Promise<AuthSession|null>;
export function createSession(ctx:Context,personId:string,amr:string[],upstreamProofId?:string|null,proof?:{localEmailVerifiedAt?:number|null;expiresAt?:number;sourceSession?:AuthSession|null;personVersion?:number|null}):Promise<{id:string;header:string}>;
export function cookie(ctx:Context,name:string,value:string,age?:number):string;
export function cookieName(ctx:Context):string;
