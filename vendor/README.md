# vendor/

Third-party browser code, committed rather than fetched at page load.

    pocketbase.umd.js   PocketBase JS SDK 0.27.0
                        sha256 544938be236b1c5df2a0fa54b714cfdabd30ccb3ba9ff0090f9c63c3a9a97221

It is here for the same reason `design-system/` is: an app should not be loading
executable code from a third party at runtime. In this file's case that argument is
sharper than usual, because this SDK is what performs the OAuth2 code exchange — it
handles the authorization code and the token that comes back. A CDN that served
something else for a few minutes would be reading sessions for every app on the
platform, and nothing in the pipeline would show it.

Pinned by version and digest. To update: replace the file, update the digest above,
and republish the template with `greenlight-app-template`.
