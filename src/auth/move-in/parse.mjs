// Pure reader for directory exports: no store, network or clock. Every source
// becomes the same staged shape, and anything unrecognised is refused plainly.
import {readCsv} from './csv.mjs';
import {CSV_SOURCES,JSON_SOURCES} from './sources.mjs';

export const MAX_FILE_BYTES=1024*1024;
export const MAX_ROWS=2000;
// Provider exports carry tens of columns; a wider file is refused while reading.
export const MAX_COLUMNS=200;
export class MoveInError extends Error { constructor(code,message) { super(message); this.code=code; } }
const refuse=(code,message)=>{throw new MoveInError(code,message);};

// Cells that a spreadsheet would run as a formula.
export const FORMULA=/^[=+\-@\t\r]/;
const clip=(value,length)=>typeof value==='string'||typeof value==='number'?String(value).trim().slice(0,length):'';

// Case-folded address, or null. The domain must be a plain ASCII host name:
// lookalike Unicode is refused rather than normalised.
export function addressOf(value) {
 const raw=clip(value,254);
 if(!raw||FORMULA.test(raw)||!/^[^\s@]+@[^\s@]+$/.test(raw))return {email:raw.toLowerCase()||null,problem:'invalid_email'};
 const email=raw.toLowerCase(),domain=email.split('@')[1];
 if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||domain.length>253)return {email,problem:/[^\x00-\x7f]/.test(domain)?'refused_domain':'invalid_email'};
 return {email,problem:null};
}
// Plus-addressed variants of one mailbox share this key.
export const mailboxOf=email=>email?email.replace(/\+[^@]*@/,'@'):null;

function exportDateOf(fileName,value) {
 const named=/jcuserlist_(\d{4})(\d{2})(\d{2})/.exec(fileName);
 const date=named?`${named[1]}-${named[2]}-${named[3]}`:String(value||'');
 if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||Number.isNaN(Date.parse(date+'T00:00:00Z')))refuse('export_date_required','Enter the date the file was exported.');
 return date;
}

function csvRecords(text) {
 let records;
 try {records=readCsv(text,MAX_ROWS+1,MAX_COLUMNS);}
 catch(error) {
  if(error.message==='too_many_columns')refuse('too_many_columns',`This file has more than ${MAX_COLUMNS} columns. Export only the user list's standard columns, then stage it.`);
  if(error instanceof RangeError)refuse('too_many_rows',`This file has more than ${MAX_ROWS} people. Split it and stage each part.`);
  refuse('file_not_recognised','This file is not readable CSV: a quoted value is never closed.');
 }
 if(!records.length)refuse('file_not_recognised','This file is empty.');
 const headers=records[0].map(h=>h.trim());
 const source=CSV_SOURCES.find(s=>s.detect(headers));
 if(!source)refuse('file_not_recognised','Auth cannot recognise this CSV. It reads the user lists exported by Google Workspace, Microsoft Entra, Auth0 and JumpCloud with their own column names.');
 const unescape=source.unescape||(value=>value);
 // Each record keeps only the columns its source reads.
 const read=source.columns.map(name=>[name,headers.indexOf(name)]).filter(([,i])=>i>=0);
 return {source,users:records.slice(1).map(record=>Object.fromEntries(read.map(([name,i])=>[name,unescape(record[i]??'')])))};
}

function jsonRecords(text) {
 let value;
 try {value=JSON.parse(text);}
 catch {
  // Auth0 bulk exports are newline-delimited JSON: one user object per line.
  try {value=text.split(/\r?\n/).filter(line=>line.trim()).map(line=>JSON.parse(line));}
  catch {refuse('file_not_recognised','This file is not readable JSON or newline-delimited JSON.');}
 }
 for(const source of JSON_SOURCES) {
  const users=source.list(value);
  if(users?.length&&users.every(user=>user&&typeof user==='object'&&!Array.isArray(user))&&users.every(source.detect))return {source,users};
 }
 refuse('file_not_recognised','Auth cannot recognise this JSON. It reads Google Workspace and JumpCloud user lists, Auth0 bulk exports and the Okta Users API list.');
}

export function parseExport({fileName,text,exportDate}) {
 if(typeof text!=='string')refuse('file_not_recognised','Choose a CSV or JSON file.');
 if(new TextEncoder().encode(text).length>MAX_FILE_BYTES)refuse('file_too_large','This file is larger than 1 MB. Export fewer columns or split it, then stage each part.');
 if(text.includes('\u0000'))refuse('file_not_recognised','This file is not text. Choose the CSV or JSON file your provider exported.');
 const name=clip(String(fileName||'').split(/[\\/]/).at(-1),200)||'export';
 const date=exportDateOf(name,exportDate);
 const body=text.replace(/^﻿/,'');
 const {source,users}=/^\s*[[{]/.test(body)?jsonRecords(body):csvRecords(body);
 if(!users.length)refuse('file_has_no_rows','This file lists no people.');
 if(users.length>MAX_ROWS)refuse('too_many_rows',`This file has more than ${MAX_ROWS} people. Split it and stage each part.`);
 const rows=users.map(user=>{
  const mapped=source.map(user),{email,problem}=addressOf(mapped.email);
  const name=clip(mapped.name,160);
  if(source.system==='custom'&&(!Array.isArray(mapped.history)||mapped.history.length>100||mapped.history.some(entry=>!entry||typeof entry.at!=='string'||!Number.isFinite(Date.parse(entry.at))||!entry.values||typeof entry.values!=='object'||Array.isArray(entry.values)||Object.entries(entry.values).some(([key,value])=>!['name','title','department','location','workerType'].includes(key)||typeof value!=='string'||value.length>320))))refuse('invalid_profile_history','Custom history must contain dated, bounded profile field snapshots.');
  return {...(source.system==='custom'?{profileHistory:mapped.history,passwordResetRequired:true,factorReenrollmentRequired:true}:{}),sourceSystem:source.system,sourceId:clip(mapped.sourceId,256)||null,email,emailProblem:problem,displayName:name||null,formulaName:FORMULA.test(name),disabled:typeof mapped.disabled==='boolean'?mapped.disabled:null,groups:mapped.groups.map(g=>clip(g,200)).filter(Boolean),exportDate:date};
 });
 return {sourceSystem:source.system,format:source.format,label:source.label,fileName:name,exportDate:date,rows};
}
