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
 *
 * Sessions are SHORT (thirty minutes) and there is no silent renewal: the server
 * refuses local token refresh on purpose, so the only way to get a new session is a
 * fresh sign-in at the identity provider — which is the one moment someone's grant is
 * re-checked. onChange fires with null the moment the session lapses; show a sign-in
 * control at that point and call signIn() from the click. Do not call signIn() on a
 * timer: a popup opened without a user gesture is blocked by the browser, and the
 * person is left looking at a page that silently stopped working.
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

  // The SDK marks a token invalid once its exp passes, but nothing tells the page
  // when that moment arrives — without this an app keeps rendering a signed-in UI
  // whose every API call now 401s. Fire onChange exactly when the session lapses so
  // the app can put a sign-in control on screen instead.
  let lapseTimer = null;

  function tokenExpiry() {
    const raw = client.authStore.token;
    if (!raw) return 0;
    try {
      let part = raw.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      part += '='.repeat((4 - (part.length % 4)) % 4);
      return (JSON.parse(atob(part)).exp || 0) * 1000;
    } catch (err) {
      return 0; // opaque token: no scheduling, the next 401 is the signal
    }
  }

  function scheduleLapse() {
    if (lapseTimer) { clearTimeout(lapseTimer); lapseTimer = null; }
    const at = tokenExpiry();
    if (!at) return;
    // +1s so the SDK's own validity check has certainly flipped when listeners run.
    const ms = at - Date.now() + 1000;
    if (ms <= 0) return;
    // setTimeout saturates above ~24.8 days; a thirty-minute token never comes close,
    // and clamping keeps a bad exp from firing the callback immediately in a loop.
    lapseTimer = setTimeout(onLapse, Math.min(ms, 2147483647));
  }

  function onLapse() {
    lapseTimer = null;
    notify(); // user() is null now: authStore.isValid went false with the exp
  }

  client.authStore.onChange(() => { scheduleLapse(); notify(); }, false);
  scheduleLapse();

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

  // Also the renewal path: a lapsed session is renewed by signing in again, not by
  // refreshing a token locally (the server refuses that). With a live SSO cookie the
  // popup completes and closes without the person touching it.
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

  function getClient() {
    return client;
  }

  return { getClient, signIn, signOut, user, isSignedIn, isAdmin, onChange };
})();
