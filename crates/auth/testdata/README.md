# Test fixtures — slauth JWKS verification

**`test_signing_key.pem` and `test_signing_key_2.pem` are throwaway RSA
keypairs generated solely for this crate's tests and for the `test-support`
feature. They are NOT secrets** and are never used for any real
authentication, in any environment. They were generated fresh for this
workspace (`openssl genrsa -traditional 2048`) — deliberately *not* copied
from any service, so that a key which ever appeared in a real config cannot
end up here.

| File | Contents |
|---|---|
| `test_signing_key.pem` | Private key for kid `stridelabs-test-key-1` (PKCS#1) |
| `test_jwks.json` | Its public half, as a one-key JWKS |
| `test_signing_key_2.pem` | Private key for kid `stridelabs-test-key-2` |
| `test_jwks_2.json` | Its public half, as a one-key JWKS |

The second pair exists so tests can express the two failures that need a key
the verifier does *not* trust: a token with a valid-looking signature made by
the wrong key, and a key rotation the JWKS cache has to notice.

They are committed on purpose — the crate embeds them with `include_str!`, so
CI needs them in the tree. The repository `.gitignore` has a global `*.pem`
rule (local mkcert/prox certs must never be committed) with an explicit `!`
exception for this directory. Do not remove that exception: without it, a
`git add -A` on a fresh clone would silently drop these files and the test
suite would stop compiling.
