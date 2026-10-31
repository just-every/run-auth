import {randomUUID} from 'node:crypto';

// Names are fresh only in test tooling. Production preserves the user's name.
export function groupNames(phase) {
 const prefix=`synthetic-auth-${phase.replace(/[^a-z0-9-]/gi,'-')}-${randomUUID()}`;
 return {create:prefix.slice(0,80),injected:(prefix+'-injected').slice(0,80)};
}

export default async function prepare({phase}) {
 return {values:{groupNames:groupNames(phase)}};
}
