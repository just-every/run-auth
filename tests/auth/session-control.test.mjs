import {test} from 'node:test';
import {nativeSessionControl} from './session-control-native.mjs';
import {sessionControlAuthority} from './session-control-authority.mjs';
import {durableSessionControl} from './session-control-durable.mjs';

test('scoped help desk ends every Auth and linked Base app session while preserving the employee and their passkey',nativeSessionControl);
test('ending another person’s sessions requires current hardware, email, permission, edit scope and strictly higher account rank at commit',sessionControlAuthority);
test('session control atomically ends refresh authority and durably reports back-channel delivery without claiming remote completion',durableSessionControl);
