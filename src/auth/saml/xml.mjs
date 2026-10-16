// A small XML reader and an exclusive XML canonicalization (exc-c14n, without
// comments) writer, enough for SAML messages, metadata and XML signatures.
// The reader refuses DOCTYPE, entity declarations and processing instructions.
import {fail} from '../core.mjs';

export const NS={saml:'urn:oasis:names:tc:SAML:2.0:assertion',samlp:'urn:oasis:names:tc:SAML:2.0:protocol',md:'urn:oasis:names:tc:SAML:2.0:metadata',ds:'http://www.w3.org/2000/09/xmldsig#',xenc:'http://www.w3.org/2001/04/xmlenc#'};
const XML_NS='http://www.w3.org/XML/1998/namespace',NAME=/^[A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?/,MAX=262144,DEPTH=48;
const ENTITIES={lt:'<',gt:'>',amp:'&',quot:'"',apos:"'"};

const decode=value=>value.replace(/&(#x[0-9a-fA-F]+|#\d+|\w+);|&/g,(m,ref)=>{
 if(!ref)fail('invalid_saml_xml');
 if(ref[0]!=='#')return ENTITIES[ref]??fail('invalid_saml_xml');
 const code=ref[1]==='x'?parseInt(ref.slice(2),16):parseInt(ref.slice(1),10);
 if(!(code===9||code===10||code===13||(code>=32&&code<=0xd7ff)||(code>=0xe000&&code<=0x10ffff&&(code<0xfffe||code>0xffff))))fail('invalid_saml_xml');
 return String.fromCodePoint(code);
});
const split=qname=>{const i=qname.indexOf(':');return i<0?['',qname]:[qname.slice(0,i),qname.slice(i+1)];};

// Element: {prefix, local, uri, attrs:[{prefix,local,uri,value}], children, scope}.
export function parseXml(input) {
 if(typeof input!=='string'||!input||input.length>MAX)fail('invalid_saml_xml');
 const text=input.replace(/^﻿/,'').replace(/\r\n?/g,'\n'),stack=[];let i=0,root=null;
 const until=(token,from)=>{const at=text.indexOf(token,from);if(at<0)fail('invalid_saml_xml');return at;};
 while(i<text.length) {
  if(text.startsWith('<?xml',i)&&i===0&&/\s/.test(text[5]??'')){i=until('?>',i)+2;continue;}
  if(text.startsWith('<!--',i)){i=until('-->',i)+3;continue;}
  if(text.startsWith('<![CDATA[',i)) {
   const end=until(']]>',i);if(!stack.length)fail('invalid_saml_xml');stack.at(-1).children.push(text.slice(i+9,end));i=end+3;continue;
  }
  if(text.startsWith('<!',i)||text.startsWith('<?',i))fail('invalid_saml_xml');
  if(text.startsWith('</',i)) {
   const end=until('>',i),name=text.slice(i+2,end).trim(),open=stack.pop();
   if(!open||open.qname!==name)fail('invalid_saml_xml');delete open.qname;i=end+1;
   if(!stack.length){if(root)fail('invalid_saml_xml');root=open;}
   continue;
  }
  if(text[i]==='<') {
   const name=NAME.exec(text.slice(i+1,i+256))?.[0]??fail('invalid_saml_xml');i+=1+name.length;
   const raw=[];
   for(;;) {
    const space=/^\s*/.exec(text.slice(i,i+4096))[0];i+=space.length;
    if(text.startsWith('/>',i)||text[i]==='>')break;
    if(!space)fail('invalid_saml_xml');
    const attr=NAME.exec(text.slice(i,i+256))?.[0]??fail('invalid_saml_xml');i+=attr.length;
    const eq=/^\s*=\s*(["'])/.exec(text.slice(i,i+64))??fail('invalid_saml_xml');i+=eq[0].length;
    const end=until(eq[1],i),value=text.slice(i,end);if(value.includes('<'))fail('invalid_saml_xml');
    raw.push([attr,decode(value.replace(/[\t\n]/g,' '))]);i=end+1;
   }
   const parent=stack.at(-1),scope={...(parent?.scope??{xml:XML_NS})},seen=new Set();
   for(const [attr,value] of raw){if(seen.has(attr))fail('invalid_saml_xml');seen.add(attr);if(attr==='xmlns')scope['']=value;else if(attr.startsWith('xmlns:'))scope[attr.slice(6)]=value;}
   const [prefix,local]=split(name),uri=scope[prefix]??(prefix?fail('invalid_saml_xml'):'');
   const attrs=raw.filter(([a])=>a!=='xmlns'&&!a.startsWith('xmlns:')).map(([a,value])=>{const [p,l]=split(a);return {prefix:p,local:l,uri:p?scope[p]??fail('invalid_saml_xml'):'',value};});
   const element={qname:name,prefix,local,uri,attrs,children:[],scope};
   if(stack.length>=DEPTH)fail('invalid_saml_xml');
   if(parent)parent.children.push(element);else if(root)fail('invalid_saml_xml');
   if(text.startsWith('/>',i)){i+=2;delete element.qname;if(!parent)root=element;}
   else {i+=1;stack.push(element);}
   continue;
  }
  const end=text.indexOf('<',i)<0?text.length:text.indexOf('<',i),value=decode(text.slice(i,end));
  if(stack.length)stack.at(-1).children.push(value);else if(value.trim())fail('invalid_saml_xml');
  i=end;
 }
 if(stack.length||!root)fail('invalid_saml_xml');
 return root;
}

// Builder: el('saml:Issuer',{Format:'...'},['text']). Prefixes resolve through NS.
export function el(qname,attrs={},children=[]) {
 const [prefix,local]=split(qname);
 return {prefix,local,uri:prefix?NS[prefix]:'',attrs:Object.entries(attrs).filter(([,v])=>v!==undefined&&v!==null).map(([name,value])=>({prefix:'',local:name,uri:'',value:String(value)})),children:children.flat().filter(c=>c!==null&&c!==undefined&&c!==false)};
}

export const children=(e,local,uri)=>e.children.filter(c=>typeof c!=='string'&&c.local===local&&(!uri||c.uri===uri));
export const child=(e,local,uri)=>children(e,local,uri)[0]??null;
export const attr=(e,name)=>e?.attrs.find(a=>!a.prefix&&a.local===name)?.value??null;
export const textOf=e=>e?e.children.map(c=>typeof c==='string'?c:textOf(c)).join(''):'';

const escText=v=>v.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\r/g,'&#xD;');
const escAttr=v=>v.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/\t/g,'&#x9;').replace(/\n/g,'&#xA;').replace(/\r/g,'&#xD;');
const compare=(a,b)=>a<b?-1:a>b?1:0;

// Exclusive canonical form of an element subtree. `omit` is a descendant left
// out (an enveloped signature); `inclusive` lists InclusiveNamespaces prefixes.
export function canonical(e,{omit=null,inclusive=[]}={}) {return render(e,{},omit,inclusive);}
function render(e,rendered,omit,inclusive) {
 const needed=new Map([[e.prefix,e.uri]]);
 for(const a of e.attrs)if(a.prefix&&a.prefix!=='xml')needed.set(a.prefix,a.uri);
 for(const token of inclusive){const p=token==='#default'?'':token;if(e.scope&&p in e.scope&&p!=='xml')needed.set(p,e.scope[p]);}
 const declared=[],next={...rendered};
 for(const [p,u] of needed) {
  if(p==='xml')continue;
  if(p===''?(rendered['']??'')===u:rendered[p]===u)continue;
  declared.push([p,u]);next[p]=u;
 }
 declared.sort((a,b)=>compare(a[0],b[0]));
 const attrs=[...e.attrs].sort((a,b)=>compare(a.uri,b.uri)||compare(a.local,b.local));
 const qname=e.prefix?`${e.prefix}:${e.local}`:e.local;
 return `<${qname}${declared.map(([p,u])=>p?` xmlns:${p}="${escAttr(u)}"`:` xmlns="${escAttr(u)}"`).join('')}${attrs.map(a=>` ${a.prefix?a.prefix+':':''}${a.local}="${escAttr(a.value)}"`).join('')}>${e.children.map(c=>typeof c==='string'?escText(c):c===omit?'':render(c,next,omit,inclusive)).join('')}</${qname}>`;
}
