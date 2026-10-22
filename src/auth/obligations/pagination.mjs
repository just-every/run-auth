import {all,b64,unb64,utf8,fail} from '../core.mjs';
// Fixed callers choose table/columns; requests supply only bound cursor values.
// (created_at,id) is a stable unique order, even when the scheduler records many
// recipients in the same millisecond. No event is discarded by pagination.
export async function obligationPage(ctx,request,{table,columns='*',prefix,defaultLimit}) {
 const params=new URL(request.url).searchParams,raw=params.get(prefix+'Cursor'),requested=params.get(prefix+'Limit');
 const limit=requested===null?defaultLimit:Number(requested);
 if(!Number.isInteger(limit)||limit<1||limit>500)fail('invalid_followup_page_limit');
 let before=null;
 if(raw!==null) {
  try {
   if(raw.length>1024||!/^[a-zA-Z0-9_-]+$/.test(raw))throw new Error();
   before=JSON.parse(new TextDecoder().decode(unb64(raw)));
   if(!Array.isArray(before)||before.length!==2||!Number.isSafeInteger(before[0])||before[0]<0||typeof before[1]!=='string'||!before[1]||before[1].length>200)throw new Error();
  }catch{fail('invalid_followup_cursor');}
 }
 const rows=await all(ctx,`SELECT ${columns} FROM ${table}${before?' WHERE created_at<? OR (created_at=? AND id<?)':''} ORDER BY created_at DESC,id DESC LIMIT ?`,...(before?[before[0],before[0],before[1]]:[]),limit+1);
 const hasMore=rows.length>limit,items=rows.slice(0,limit),last=items.at(-1);
 return {items,page:{hasMore,nextCursor:hasMore?b64(utf8.encode(JSON.stringify([last.created_at,last.id]))):null}};
}
