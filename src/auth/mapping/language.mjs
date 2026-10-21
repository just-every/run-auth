import {fail} from '../core.mjs';

export const LANGUAGE_VERSION = 1;
export const EXPRESSION_LIMITS = Object.freeze({maxNodes:128,maxDepth:16,maxLiteralLength:1024,maxStringLength:4096,maxListLength:256,maxTotalLength:16384,maxPatternLength:128,maxSteps:1000000,maxMs:10});
const TYPES = new Set(['text','number','boolean','date','person','choice']);
const SOURCES = new Set(['manual','hr','directory','self']);
const BUILTINS = {email:'text',name:'text',person_id:'text',first_name:'text',last_name:'text'};
const TEXT = new Set(['text','date','person','choice']);
const MODES = ['equals','contains','startsWith','endsWith'];
const FORMATS = ['YYYY-MM-DD','YYYYMMDD','MM/DD/YYYY','YYYY-MM-DDTHH:mm:ssZ'];
const invalid = () => fail('mapping_invalid_expression');
const typeError = () => fail('mapping_type');
const exceeded = () => fail('mapping_budget');
const plain = value => value !== null && typeof value === 'object' && [Object.prototype,null].includes(Object.getPrototypeOf(value));
const own = (value,key) => plain(value) && Object.hasOwn(value,key);
function read(value,key) {
 if (!own(value,key)) return undefined;
 const descriptor = Object.getOwnPropertyDescriptor(value,key);
 if (!Object.hasOwn(descriptor,'value')) invalid();
 return descriptor.value;
}
function keys(value,allowed) {
 if (!plain(value) || Object.keys(value).some(key=>!allowed.includes(key))) invalid();
 for (const key of Object.keys(value)) read(value,key);
}
function arrayValues(value,limit) {
 if (!Array.isArray(value)) typeError();
 if (value.length>limit) exceeded();
 const result=[];
 for (let index=0;index<value.length;index++) {
  const descriptor=Object.getOwnPropertyDescriptor(value,String(index));
  if (!descriptor || !Object.hasOwn(descriptor,'value')) invalid();
  result.push(descriptor.value);
 }
 return result;
}
function fieldName(name) {
 if (typeof name !== 'string' || !/^(?:x\.)?[a-z][a-z0-9_]{0,63}$/.test(name)
  || /(?:^|_)(?:secret|secrets|token|tokens|password|passkey|credential|credentials|key|keys)(?:_|$)/.test(name)) invalid();
 return name;
}
function root(expression) {
 if (own(expression,'version')) {
  keys(expression,['version','expression']);
  if (read(expression,'version') !== LANGUAGE_VERSION || !own(expression,'expression')) invalid();
  return read(expression,'expression');
 }
 return expression;
}
const compatible = (actual,expected) => actual === 'null' || actual === expected || expected === 'text' && TEXT.has(actual);
function common(types) {
 const present = types.filter(type=>type !== 'null');
 if (!present.length) return 'null';
 if (present.every(type=>type === present[0])) return present[0];
 if (present.every(type=>TEXT.has(type))) return 'text';
 typeError();
}
function lookupType(schema,kind,field,runtime) {
 fieldName(field);
 const map = kind === 'manager' ? read(schema,'manager') ?? read(schema,'fields') : read(schema,'fields');
 const type = read(map,field) ?? BUILTINS[field];
 if (!TYPES.has(type) && !(runtime && type === 'null')) invalid();
 return type;
}

// Validation walks every branch, including branches runtime short-circuits.
function inspect(expression,schema,tick,runtime=false) {
 keys(schema,['fields','manager']);
 let count = 0;
 function visit(node,depth) {
  tick();
  if (++count > EXPRESSION_LIMITS.maxNodes || depth > EXPRESSION_LIMITS.maxDepth) exceeded();
  if (node === null) return 'null';
  if (typeof node === 'string') { if (node.length > EXPRESSION_LIMITS.maxLiteralLength) exceeded(); return 'text'; }
  if (typeof node === 'boolean') return 'boolean';
  if (typeof node === 'number' && Number.isFinite(node)) return 'number';
  if (!plain(node)) invalid();
  if (own(node,'source')) {
   keys(node,['source','field']);
   if (!SOURCES.has(read(node,'source'))) invalid();
   return lookupType(schema,'fields',read(node,'field'),runtime);
  }
  if (own(node,'field')) { keys(node,['field']); return lookupType(schema,'fields',read(node,'field'),runtime); }
  if (own(node,'manager')) { keys(node,['manager']); return lookupType(schema,'manager',read(node,'manager'),runtime); }
  if (own(node,'groups')) { keys(node,['groups']); if (read(node,'groups') !== true) invalid(); return 'list'; }
  keys(node,['op','args']);
  const op = read(node,'op'), rawArgs = read(node,'args');
  if (!Array.isArray(rawArgs)) invalid();
  const args=arrayValues(rawArgs,EXPRESSION_LIMITS.maxNodes);
  const types = args.map(arg=>visit(arg,depth+1));
  const arity = (min,max=min) => { if (args.length < min || args.length > max) invalid(); };
  const at = (index,type) => { if (!compatible(types[index],type)) typeError(); };
  const textArgs = () => types.forEach((_,index)=>at(index,'text'));
  switch (op) {
   case 'concat': arity(1,128); textArgs(); return 'text';
   case 'lower': case 'upper': case 'trim': arity(1); at(0,'text'); return 'text';
   case 'substring': arity(2,3); at(0,'text'); at(1,'number'); if (args.length === 3) at(2,'number'); return 'text';
   case 'replace': arity(3); textArgs(); if (args[1] === '') invalid(); return 'text';
   case 'regexReplace': arity(3); textArgs(); if (typeof args[1] !== 'string') invalid(); pattern(args[1],tick); return 'text';
   case 'pad': arity(2,4); at(0,'text'); at(1,'number'); if (args.length > 2) at(2,'text'); if (args.length > 3 && !['start','end'].includes(args[3])) invalid(); return 'text';
   case 'if': arity(3); at(0,'boolean'); return common(types.slice(1));
   case 'coalesce': arity(1,128); return common(types);
   case 'date': arity(2); at(0,'text'); if (!FORMATS.includes(args[1])) invalid(); return 'text';
   case 'inGroup': arity(1); at(0,'text'); return 'boolean';
   case 'filter': arity(3); at(0,'list'); if (!MODES.includes(args[1])) invalid(); at(2,'text'); return 'list';
   case 'eq': arity(2); if (types.includes('list')) typeError(); common(types); return 'boolean';
   default: invalid();
  }
 }
 return visit(root(expression),1);
}

export function validateExpression(expression,schema) {
 return inspect(expression,schema,()=>{});
}

// The regex grammar has character atoms and ?, *, +, without groups,
// alternation, lookaround or backreferences. Single-character predicates only.
function pattern(source,tick) {
 if (!source || source.length > EXPRESSION_LIMITS.maxPatternLength) invalid();
 let index = 0;
 const start = source[index] === '^'; if (start) index++;
 const tokens = [];
 function atom(inClass=false) {
  const char = source[index++];
  if (char === undefined) invalid();
  if (char === '\\') {
   const escaped = source[index++];
   if (!escaped) invalid();
   const classes = {d:c=>c>='0'&&c<='9',w:c=>/[a-zA-Z0-9_]/.test(c),s:c=>/\s/.test(c)};
   if (classes[escaped.toLowerCase()]) {
    const test = classes[escaped.toLowerCase()];
    return {test:escaped === escaped.toLowerCase()?test:c=>!test(c)};
   }
   if (!'\\.^$[]()*+?{}|-'.includes(escaped)) invalid();
   return {test:c=>c===escaped,literal:escaped};
  }
  if (!inClass && char === '.') return {test:c=>c!=='\n'&&c!=='\r'};
  if ((!inClass && '^$[]()*+?{}|'.includes(char)) || inClass && '[]'.includes(char)) invalid();
  return {test:c=>c===char,literal:char};
 }
 while (index < source.length && !(source[index] === '$' && index === source.length-1)) {
  tick();
  let test,cost=1;
  if (source[index] === '[') {
   index++;
   const negate = source[index] === '^'; if (negate) index++;
   const members = [];
   while (index < source.length && source[index] !== ']') {
    const left = atom(true);
    if (source[index] === '-' && source[index+1] !== ']') {
     index++; const right = atom(true);
     if (left.literal === undefined || right.literal === undefined || left.literal > right.literal) invalid();
     members.push(c=>c>=left.literal&&c<=right.literal);
    } else members.push(left.test);
   }
   if (source[index++] !== ']' || !members.length) invalid();
   test = c=>members.some(member=>member(c)) !== negate; cost=members.length;
  } else test = atom().test;
  const quantifier = '?*+'.includes(source[index] ?? '\0') ? source[index++] : '';
  tokens.push({test,quantifier,cost});
 }
 const end = source[index] === '$'; if (end) index++;
 if (index !== source.length || !tokens.length) invalid();
 return {tokens,start,end};
}

// Dynamic programming computes the greedy match endpoint at every starting
// offset in O(input length * pattern size), including failed matches.
function regexReplace(value,source,replacement,tick,bound) {
 const {tokens,start,end} = pattern(source,tick), length = value.length;
 let next = new Int32Array(length+1);
 for (let pos=0;pos<=length;pos++) next[pos] = !end || pos===length ? pos : -1;
 for (let token=tokens.length-1;token>=0;token--) {
  const {test,quantifier:q,cost} = tokens[token], current = new Int32Array(length+1).fill(-1);
  tick((length+1)*cost);
  for (let pos=length;pos>=0;pos--) {
   if (pos % 64 === 0) tick();
   const matches = pos<length && test(value[pos]);
   if (q === '*' || q === '+') {
    const repeated = matches ? current[pos+1] : -1;
    // '+' takes one atom, then the '*' continuation (including zero more).
    const taken = matches ? (repeated>=0?repeated:next[pos+1]) : -1;
    current[pos] = q === '*' ? (taken>=0?taken:next[pos]) : taken;
   } else if (q === '?') current[pos] = matches && next[pos+1]>=0 ? next[pos+1] : next[pos];
   else if (matches) current[pos] = next[pos+1];
  }
  next = current;
 }
 const parts=[]; let outputLength=0,cursor=0;
 const append=part=>{tick(part.length+1);outputLength+=part.length;if(outputLength>EXPRESSION_LIMITS.maxStringLength)exceeded();parts.push(part);};
 while (cursor<=length) {
  tick();
  const endpoint = (!start || cursor===0) ? next[cursor] : -1;
  if (endpoint<0) { if (cursor<length) append(value[cursor]); cursor++; continue; }
  append(replacement);
  if (endpoint===cursor) { if (cursor<length) append(value[cursor]); cursor++; }
  else cursor=endpoint;
 }
 return bound(parts.join(''));
}

function runtimeSchema(context) {
 const infer = map => {
  if (map === undefined || map === null) return {};
  if (!plain(map) || Object.keys(map).length > 512) invalid();
  return Object.fromEntries(Object.keys(map).map(key=>{
   const value = read(map,key);
   return [key,value === null ? 'null' : typeof value === 'string' ? 'text' : typeof value === 'number' ? 'number' : typeof value === 'boolean' ? 'boolean' : invalid()];
  }));
 };
 const fields = infer(read(context,'fields')), manager = infer(read(context,'manager'));
 const sources = read(context,'sources');
 if (sources !== undefined) {
  keys(sources,[...SOURCES]);
  for (const source of SOURCES) for (const [key,type] of Object.entries(infer(read(sources,source)))) {
   if (!Object.hasOwn(fields,key) || fields[key] === 'null') fields[key] = type;
  }
 }
 return {fields,manager};
}

export function evaluateExpression(expression,context,budget={}) {
 if (!plain(context)) invalid();
 if (typeof budget === 'number') budget = {steps:budget};
 keys(budget,['steps','maxMs']);
 const steps = read(budget,'steps') ?? EXPRESSION_LIMITS.maxSteps, maxMs = read(budget,'maxMs') ?? EXPRESSION_LIMITS.maxMs;
 if (!Number.isInteger(steps) || steps<1 || steps>EXPRESSION_LIMITS.maxSteps || typeof maxMs !== 'number' || !Number.isFinite(maxMs) || maxMs<=0 || maxMs>EXPRESSION_LIMITS.maxMs) exceeded();
 const started = performance.now(); let remaining = steps;
 const tick = (cost=1) => { remaining-=cost; if (remaining<0 || performance.now()-started>maxMs) exceeded(); };
 const bound = value => {
  tick(typeof value === 'string' ? value.length : 1);
  if (typeof value === 'string' && value.length>EXPRESSION_LIMITS.maxStringLength) exceeded();
  if (typeof value === 'number' && !Number.isFinite(value)) typeError();
  if (value !== null && !['string','number','boolean'].includes(typeof value) && !Array.isArray(value)) typeError();
  if (Array.isArray(value)) {
   if (value.length>EXPRESSION_LIMITS.maxListLength) exceeded();
   let total = 0; for (const item of arrayValues(value,EXPRESSION_LIMITS.maxListLength)) { if (typeof item !== 'string') typeError(); bound(item); total+=item.length; }
   if (total>EXPRESSION_LIMITS.maxTotalLength) exceeded();
  }
  return value;
 };
 const schema = runtimeSchema(context);
 inspect(expression,schema,tick,true);
 const groupNames = () => bound(arrayValues(read(context,'groups') ?? [],EXPRESSION_LIMITS.maxListLength));
 const integer = value => { if (!Number.isInteger(value) || value<0 || value>EXPRESSION_LIMITS.maxStringLength) typeError(); return value; };
 function run(node) {
  tick();
  if (node === null || typeof node !== 'object') return bound(node);
  if (own(node,'source')) return bound(read(read(read(context,'sources'),node.source),node.field) ?? null);
  if (own(node,'field')) return bound(read(read(context,'fields'),node.field) ?? null);
  if (own(node,'manager')) return bound(read(read(context,'manager'),node.manager) ?? null);
  if (own(node,'groups')) return groupNames();
  const {op,args} = node;
  if (op === 'if') { const condition=run(args[0]); if (condition!==null && typeof condition!=='boolean') typeError(); return run(args[condition===true?1:2]); }
  if (op === 'coalesce') { for (const arg of args) { const value=run(arg); if (value!==null) return value; } return null; }
  const values = args.map(run), [value,a,b,c] = values;
  if (op === 'eq') return value===a;
  const string = item=>{if(item!==null && typeof item!=='string')typeError();};
  if (op === 'inGroup') { string(value); return value === null ? false : groupNames().includes(value); }
  if (op === 'filter') { if(value!==null&&!Array.isArray(value))typeError();string(b);return value === null || b === null ? [] : bound(value.filter(item=>{tick(item.length+b.length);return a==='equals'?item===b:item[a==='contains'?'includes':a](b);})); }
  if (op === 'substring' || op === 'pad') { string(value); if(op==='pad'&&values.length>2)string(b); }
  else values.forEach(string);
  if (values.includes(null)) return null;
  let output;
  switch (op) {
   case 'concat': if (values.reduce((sum,item)=>sum+item.length,0)>EXPRESSION_LIMITS.maxStringLength) exceeded(); output=values.join(''); break;
   case 'lower': output=value.toLowerCase(); break;
   case 'upper': output=value.toUpperCase(); break;
   case 'trim': output=value.trim(); break;
   case 'substring': output=value.slice(integer(a),b===undefined?undefined:integer(a)+integer(b)); break;
   case 'replace': {
    if (!a) invalid(); let cursor=0; output='';
    for (;;) { tick(value.length); const found=value.indexOf(a,cursor); if (found<0) { output=bound(output+value.slice(cursor)); break; } output=bound(output+value.slice(cursor,found)+b); cursor=found+a.length; }
    break;
   }
   case 'regexReplace': output=regexReplace(value,a,b,tick,bound); break;
   case 'pad': { const width=integer(a),fill=b??' '; if (!fill) invalid(); output=c==='end'?value.padEnd(width,fill):value.padStart(width,fill); break; }
   case 'date': {
    if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z)?$/.test(value)) typeError();
    const parsed=new Date(value.length===10?value+'T00:00:00Z':value);
    if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0,10)!==value.slice(0,10)) typeError();
    const iso=parsed.toISOString(), y=iso.slice(0,4),m=iso.slice(5,7),d=iso.slice(8,10);
    output=a==='YYYYMMDD'?y+m+d:a==='MM/DD/YYYY'?m+'/'+d+'/'+y:a==='YYYY-MM-DDTHH:mm:ssZ'?iso.slice(0,19)+'Z':iso.slice(0,10); break;
   }
   default: invalid();
  }
  return bound(output);
 }
 const output=run(root(expression)); tick(); return output;
}
