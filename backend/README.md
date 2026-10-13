# Authentication and vault-key boundary

VaultX uses the `server-blind-envelope` key-bundle mode. The browser creates
random vault keys and sends only AES-GCM ciphertext, IVs, authenticated bundle
metadata, and the public key. The API persists and returns those opaque values;
it has no endpoint that accepts plaintext vault keys or a decrypted private
key. Login passwords are still submitted to the authentication endpoint for
the bcrypt account check, so this implementation is **not** a PAKE/OPAQUE
protocol and makes no zero-knowledge claim. A cryptographic PAKE migration
requires a separately reviewed protocol and client/server rollout.

Administrative APIs fail closed unless the identity has the `admin` role, has
enrolled MFA, and has a recent MFA assertion in the access token. The role map
is expressed as named permissions in `app/core/permissions.py`; this keeps
authorization decisions granular without changing existing endpoint paths.

`KEY_BUNDLE_MODE` is fixed to `server-blind-envelope`; startup rejects any
other value rather than silently falling back to plaintext key handling.
