export const TITLES={new_device:'Auth sign-in from a new browser',factor_enrolled:'Auth sign-in factor enrolled',factor_reset:'Auth sign-in factor reset',factor_removed:'Auth sign-in factor removed',recovery_started:'Auth recovery started',administrator_role_granted:'Auth administrator role granted'};
const clean=(value,length=200)=>String(value??'').replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,length);
export function notificationContext(ctx,{request,app,factor}) {
 const cf=request?.cf;
 return {app:clean(app??'Auth'),time:new Date(ctx.now()).toISOString(),location:clean([cf?.city,cf?.region,cf?.country].filter(Boolean).join(', ')||'Unavailable'),ip:clean(request?.headers.get('cf-connecting-ip')??'Unavailable',64),device:clean(request?.headers.get('user-agent')??'Unavailable',300),...(factor?{factor:clean(factor)}:{})};
}
export function notificationMessage(ctx,row,link) {
 const c=JSON.parse(row.context),home=`${ctx.origin}${ctx.basePath??''}`;
 const lines=[TITLES[row.event],`App: ${c.app}`,`Time: ${c.time}`,`Approximate location: ${c.location}`,`IP: ${c.ip}`,`Device: ${c.device}`];
 if(c.factor)lines.push(`Factor: ${c.factor}`);
 if(row.event==='recovery_started')lines.push(`To cancel this recovery, sign in and open My account: ${home}/app/account`);
 lines.push(`Report suspicious activity: ${link}`,'The report link expires in 7 days and can be used once. It cannot sign you in.');
 return {subject:TITLES[row.event],text:lines.join('\n')};
}
