import {all,requireSession,json} from '../core.mjs';

export async function deliveryModel(ctx) {
 return {provider:ctx.mailProvider??'configured',eventsConfigured:ctx.mailProvider==='sendgrid'&&Boolean(ctx.sendgridWebhookKey),
  attempts:await all(ctx,"SELECT id,provider,CASE WHEN state='dispatching' THEN 'uncertain' ELSE state END AS state,created_at,updated_at,error FROM auth_mail_deliveries ORDER BY created_at DESC,rowid DESC LIMIT 100"),
  suppressed:(await ctx.db.prepare('SELECT COUNT(*) AS count FROM auth_mail_suppressions').first()).count};
}
export async function deliveryRead(ctx,request) {
 await requireSession(ctx,request,true);return json(await deliveryModel(ctx));
}
