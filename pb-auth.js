/* pb-auth.js — the single seam between this app and its backend identity.
 *
 * Today: an anonymous, persisted, crypto-random owner id. That id gives
 * PERSISTENCE, not security — anyone holding it can read/write its rows.
 * Don't build anything on this that would hurt if a row leaked.
 *
 * Upgrade path to real auth: change the internals here (and the collection
 * rules to `@request.auth.id`); app code using PBAuth stays unchanged.
 */
const PBAuth = (() => {
  const KEY = 'solhann_owner_id';

  function ownerId() {
    let id = localStorage.getItem(KEY);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(KEY, id);
    }
    return id;
  }

  function getClient() {
    // Same-origin: Caddy fronts this app's own PocketBase instance, no CORS.
    const client = new PocketBase(location.origin);
    // Every request carries the owner id; collection rules key on it
    // (owner = @request.headers.x_owner).
    client.beforeSend = (url, options) => {
      options.headers = { ...(options.headers || {}), 'X-Owner': ownerId() };
      return { url, options };
    };
    return client;
  }

  return { getClient, ownerId };
})();
