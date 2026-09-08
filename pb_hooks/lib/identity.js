/*
 * lib/identity.js — the one identity resolver used by the Access service.
 *
 * PocketBase record ids and email addresses are local/display identifiers.  The
 * provider id on the OIDC external-auth link is the canonical Keycloak subject and
 * is the only value that may be used for grants, authorisation or audit actors.
 */
module.exports = {
  subjectForRecord(app, record) {
    if (!record || record.collection().name !== "users") return null;

    const links = app.findAllExternalAuthsByRecord(record);
    let subject = null;
    for (let i = 0; i < links.length; i++) {
      if (!links[i] || links[i].provider() !== "oidc") continue;
      const found = "" + (links[i].providerId() || "");
      if (!found) continue;
      if (subject && subject !== found) {
        throw new Error("the Access user has more than one canonical OIDC subject");
      }
      subject = found;
    }
    return subject;
  },

  currentAdmin(app, record) {
    const subject = this.subjectForRecord(app, record);
    if (!subject) return null;
    try {
      const grant = app.findFirstRecordByFilter(
        "grants",
        "subject = {:s} && slug = 'id-admin'",
        { s: subject },
      );
      return grant.get("role") === "admin" ? subject : null;
    } catch (err) {
      return null;
    }
  },
};
