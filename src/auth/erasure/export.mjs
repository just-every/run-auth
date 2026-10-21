import {all} from '../core.mjs';
import {signToken} from '../keys.mjs';
import {JOURNAL_FORMAT,sourceOf,organizationOf} from './journal.mjs';

export const entryOf=row=>({id:row.id,source:row.source,organization:row.organization,kind:row.kind,reference:row.reference,
 hashes:JSON.parse(row.hashes),records:JSON.parse(row.records),createdAt:row.created_at});
export async function signedJournal(ctx,nextEntry=null) {
 const entries=(await all(ctx,'SELECT * FROM auth_erasure_journal ORDER BY seq')).map(entryOf);
 if(nextEntry)entries.push(nextEntry);
 const payload={format:JOURNAL_FORMAT,version:1,issuer:sourceOf(ctx),organization:organizationOf(ctx),createdAt:ctx.now(),entries};
 const proof=await signToken({...ctx,origin:sourceOf(ctx)},{...payload,aud:sourceOf(ctx)},{typ:'erasure-journal+jwt',published:true,expiresAt:Math.floor(ctx.now()/1000)+7*365*86400});
 const keys=(await all(ctx,'SELECT public_jwk FROM auth_signing_keys WHERE retire_at IS NULL OR retire_at>?',ctx.now())).map(row=>JSON.parse(row.public_jwk));
 return {...payload,jwks:{keys},proof};
}
