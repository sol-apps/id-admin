/* pb-auth.js — the single seam between this app and platform identity.
 *
 * People sign in once, at id.solhann.net, and the identity provider decides whether
 * they may enter THIS app at all: someone without a grant never reaches this file,
 * because they never get an authorization code. So the questions worth asking here
 * are "who is this" and "are they an admin of this app", not "are they allowed in".
 *
 * Do not reimplement any of this in app code, and do not read `role` from anywhere
 * but the record — it is set server-side from the identity provider's claim on every
 * login (pb_hooks/identity.pb.js) and cannot be set by the browser.
 *
 *   PBAuth.getClient()          PocketBase client, authenticated if signed in
 *   PBAuth.signIn()             start the OIDC login (returns a promise)
 *   PBAuth.signOut()            clear the local session
 *   PBAuth.user()               the signed-in record, or null
 *   PBAuth.isSignedIn()
 *   PBAuth.isAdmin()            true when this person is an admin OF THIS APP
 *   PBAuth.onChange(fn)         called whenever sign-in state changes
 *   PBAuth.requireSignIn()      render nothing until signed in; resolves when ready
 *
 * Collection rules key on `@request.auth.id`. An app whose rules key on anything the
 * browser can choose has no access control, only decoration.
 */
const PBAuth = (() => {
  const client = new PocketBase(location.origin);
  const listeners = [];

  function notify() {
    const u = user();
    listeners.forEach((fn) => {
      try { fn(u); } catch (err) { console.error('[pb-auth] listener failed', err); }
    });
  }

  client.authStore.onChange(notify, false);

  function user() {
    return client.authStore.isValid ? client.authStore.record : null;
  }

  function isSignedIn() {
    return !!user();
  }

  // Authoritative because it is server-set. The hook writes it from the app-admin
  // client role on every login, so a revoked admin grant is gone at the next sign-in
  // without anyone editing a record.
  function isAdmin() {
    const u = user();
    return !!u && u.role === 'admin';
  }

  async function signIn() {
    // Opens the IdP in a popup and completes the code exchange. If this person has
    // no grant for this app, the popup shows the IdP's refusal and this rejects —
    // which is the correct place for that to happen, not here.
    await client.collection('users').authWithOAuth2({ provider: 'oidc' });
    return user();
  }

  function signOut() {
    // Clears THIS app's session. The person stays signed in at the IdP, which is the
    // point of one login for the platform; signing out everywhere is a session
    // operation on the IdP, not something an app may do to its neighbours.
    client.authStore.clear();
  }

  function onChange(fn) {
    listeners.push(fn);
    fn(user());
    return () => {
      const i = listeners.indexOf(fn);
      if (i !== -1) listeners.splice(i, 1);
    };
  }

  async function requireSignIn() {
    if (isSignedIn()) return user();
    return signIn();
  }

  function getClient() {
    return client;
  }

  return { getClient, signIn, signOut, user, isSignedIn, isAdmin, onChange, requireSignIn };
})();
