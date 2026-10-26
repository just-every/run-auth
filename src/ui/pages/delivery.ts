import {escape,timeElement} from '../helpers.js'

export interface DeliveryModel {
 provider:string;eventsConfigured:boolean;suppressed:number
 attempts:Array<{id:string;provider:string;state:string;created_at:number;updated_at:number;error:string|null}>
}
export function deliveryPanel(model?:DeliveryModel):string {
 if(!model)return ''
 const state=(value:string)=>value.replaceAll('_',' ')
 return `<section class="panel stacked" aria-label="Mail delivery"><div class="panel-header"><div><h2>Mail delivery</h2><p>Provider acceptance is separate from delivery. An uncertain attempt is never resent automatically.</p></div></div><p>${escape(model.provider==='development'?'Private local outbox. No external mail is sent.':`Transport: ${model.provider}. ${model.eventsConfigured?'Signed SendGrid events configured.':'Provider delivery events are not configured.'}`)}</p><p>${model.suppressed} suppressed ${model.suppressed===1?'recipient':'recipients'}</p><details><summary>Recent delivery attempts</summary>${model.attempts.length?`<div class="data-list">${model.attempts.map(attempt=>`<article class="stacked"><strong>${escape(state(attempt.state))}</strong><span>${timeElement(attempt.created_at)}</span><span>Reference: ${escape(attempt.id.slice(0,12))}</span>${attempt.error?`<span>${escape(state(attempt.error))}</span>`:''}</article>`).join('')}</div>`:'<p>No delivery attempts recorded.</p>'}</details></section>`
}
