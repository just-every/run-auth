import {email as normalizeEmail} from '../core.mjs';
import {identifier,invalid,object} from './network.mjs';

export function text(value,maximum=160) {
 if(value===undefined||value===null||value==='')return null;
 if(typeof value!=='string'||value.length>maximum||/[\x00-\x1f\x7f]/.test(value))invalid();
 return value.trim()||null;
}
export function fields(values) {
 const result={};
 for(const [key,value] of Object.entries(values)){const normalized=text(value,key==='title'||key==='department'||key==='location'?120:160);if(normalized!==null)result[key]=normalized;}
 return result;
}
export function user(row,{email,name,active,profile={}}) {
 if(!object(row)||typeof active!=='boolean')invalid();
 const address=normalizeEmail(email);if(!address||address.length>254)invalid();
 const label=text(name)??address;
 return {sourceId:identifier(row.id),email:address,name:label,active,fields:{name:label,...fields(profile)}};
}
export function group(row,name,members,net) {
 const memberIds=[],seen=new Set();
 for(const value of members){const id=identifier(value);if(seen.has(id))invalid();seen.add(id);memberIds.push(id);}
 net.countMembers(memberIds.length);
 return {sourceId:identifier(row.id),name:text(name)??invalid(),memberIds};
}
export function validateReferences(users,groups) {
 const known=new Set(users.map(person=>person.sourceId));
 // Nested groups and external members cannot silently become local people.
 // Refuse rather than presenting a partial membership list as complete.
 for(const entry of groups)for(const member of entry.memberIds)if(!known.has(member))invalid();
}
