import {nativePerson} from './native-person.mjs';

/** An invited worker becomes a native identity through their own email and
 * passkey enrollment. This is a fixture person, not another Business sponsor. */
export default async function initialize(options) {
 return (await nativePerson(options)).response;
}
