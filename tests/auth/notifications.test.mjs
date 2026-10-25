import {test} from 'node:test';
import {notificationsFlow,notificationsSafety} from './notifications-flow.mjs';
test('security notifications report suspicious activity, escalate once and end sessions and refresh grants with back-channel logout',notificationsFlow);
test('security notice preferences retain mandatory recovery and factor notices, and report links refuse forgery, cross-employer use and expiry',notificationsSafety);
