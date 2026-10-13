// Auth proof belongs to the requesting browser. A CLI must not mail a link
// bound to its own transient cookie jar and present it as a usable sign-in.
export async function browserSignIn(context) {
 const response = await fetch(new URL('/.well-known/openid-configuration', context.origin), { signal: context.signal });
 if (!response.ok) throw context.fail('setup');
 await response.body?.cancel();
 await context.store.step('Open Auth and request your email link in that browser');
 return new URL('/signin?returnTo=%2Fsetup', context.origin).href;
}

export function browserInstaller(install) {
 return async (root, input, store, onApp, signal) => {
  const wrapped = Object.create(store);
  wrapped.phase = async phase => {
   if (phase === 'complete' && store.state.appUrl) {
    store.state.appUrl = new URL('/signin?returnTo=%2Fsetup', store.state.appUrl).href;
    store.state.devOpen = false;
   }
   return store.phase(phase);
  };
  return install(root, input, wrapped, onApp, signal);
 };
}
