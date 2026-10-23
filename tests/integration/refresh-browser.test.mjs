import {test} from 'node:test';
import {refreshJourney} from './helpers/refresh-journey.mjs';

test('offline app journey: publish a profile, consent to a native device, inspect and revoke it through My account at 1440 and 390',{timeout:420000},refreshJourney);
