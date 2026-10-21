import {fail} from '../../core.mjs';

function ipv4(text) {
 const parts=text.split('.');
 if(parts.length!==4||parts.some(p=>! /^(0|[1-9][0-9]{0,2})$/.test(p)||Number(p)>255))return null;
 return parts.reduce((n,p)=>(n<<8n)|BigInt(p),0n);
}
function address(text) {
 if(typeof text!=='string'||!text||text.includes('%'))return null;
 if(!text.includes(':')){const value=ipv4(text);return value===null?null:{bits:32,value};}
 let source=text.toLowerCase();
 if(source.includes('.')) {
  const at=source.lastIndexOf(':'),tail=ipv4(source.slice(at+1));
  if(tail===null)return null;
  source=source.slice(0,at+1)+(tail>>16n).toString(16)+':'+(tail&65535n).toString(16);
 }
 const halves=source.split('::');if(halves.length>2)return null;
 const left=halves[0]?halves[0].split(':'):[],right=halves.length===2&&halves[1]?halves[1].split(':'):[];
 if([...left,...right].some(p=>!/^[0-9a-f]{1,4}$/.test(p)))return null;
 if(halves.length===1&&left.length!==8||halves.length===2&&left.length+right.length>=8)return null;
 const parts=[...left,...Array(8-left.length-right.length).fill('0'),...right];
 return {bits:128,value:parts.reduce((n,p)=>(n<<16n)|BigInt('0x'+p),0n)};
}
function network(text) {
 if(typeof text!=='string'||text!==text.trim())return null;
 const parts=text.split('/');if(parts.length>2)return null;
 const ip=address(parts[0]);if(!ip)return null;
 const prefix=parts.length===1?ip.bits:/^(0|[1-9][0-9]{0,2})$/.test(parts[1])?Number(parts[1]):-1;
 return prefix<0||prefix>ip.bits?null:{...ip,prefix};
}
export function allowedIps(value) {
 if(value===undefined)return [];
 if(!Array.isArray(value)||value.length>100)fail('invalid_admin_service_ips');
 return [...new Set(value.map(v=>{if(!network(v))fail('invalid_admin_service_ips');return v.toLowerCase();}))];
}
// Cloudflare supplies this header at the trusted Worker boundary. Forwarded and
// X-Forwarded-For are deliberately not accepted as alternate address sources.
export function permitsIp(allowlist,request) {
 if(!allowlist.length)return true;
 const ip=address(request.headers.get('cf-connecting-ip')||'');if(!ip)return false;
 return allowlist.some(text=>{const net=network(text);if(!net||net.bits!==ip.bits)return false;const shift=BigInt(ip.bits-net.prefix);return (ip.value>>shift)===(net.value>>shift);});
}
