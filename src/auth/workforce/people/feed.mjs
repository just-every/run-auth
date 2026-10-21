// A source's records (the HR system, a directory feed) become edits of the people
// they identify. A person is found by the source's own identifier, never by
// email: an unknown identifier whose email matches someone waits for an
// administrator to say which person it is, and nothing is merged.
import {email as normalizeEmail} from '../../core.mjs';
import {FEED_SOURCES} from './fields.mjs';

const MAX_RECORDS=200;
export function feedEdits(dir,source,records) {
 const edits=[],outcomes=[];
 if(!FEED_SOURCES.includes(source)||!Array.isArray(records)||!records.length||records.length>MAX_RECORDS)return null;
 for(const record of records) {
  const sourceId=String(record?.sourceId??'').trim().slice(0,128);
  if(!sourceId){outcomes.push({sourceId,outcome:'invalid_record'});continue;}
  const set=record.fields&&typeof record.fields==='object'?record.fields:{};
  const bound=dir.sources.get(`${source}:${sourceId}`);
  if(bound&&record.personId&&String(record.personId)!==bound){outcomes.push({sourceId,outcome:'refused',refusals:['source_id_in_use']});continue;}
  if(bound){edits.push({personId:bound,source,set});outcomes.push({sourceId,personId:bound,outcome:'matched',edit:edits.length-1});continue;}
  // The administrator's review: this identifier is that person, bound once and for good.
  if(record.personId){edits.push({personId:String(record.personId),source,set,bind:{source,sourceId}});outcomes.push({sourceId,personId:String(record.personId),outcome:'bound_by_review',edit:edits.length-1});continue;}
  const candidate=dir.byEmail.get(normalizeEmail(record.email)||'');
  outcomes.push(candidate?{sourceId,outcome:'review_required',candidate:{personId:candidate.id,email:candidate.email,state:candidate.state}}:{sourceId,outcome:'unmatched'});
 }
 return {edits,outcomes};
}
