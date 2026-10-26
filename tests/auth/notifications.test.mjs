import {test} from 'node:test';
import {notificationsFlow,notificationsSafety} from './notifications-flow.mjs';
import {deliveryReconciliation,deliveryFailures} from './delivery-flow.mjs';
test('security notifications report suspicious activity, escalate once and end sessions and refresh grants with back-channel logout',notificationsFlow);
test('security notice preferences retain mandatory recovery and factor notices, and report links refuse forgery, cross-employer use and expiry',notificationsSafety);
test('mail delivery reconciles signed recipient-bound events, survives restart, suppresses bounced recipients and keeps diagnostic exports private',deliveryReconciliation);
test('mail failures and throttling retain unresolved employee enrollment without replaying uncertain sends',deliveryFailures);
