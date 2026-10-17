# Known-answer fixtures

Generated once, by the build before the crypto-crate upgrade, and checked in so that every
later build has to read what that one wrote: a tenant CA and the agent certificates it
issued, the bundle-signing key pair, and the server's mTLS certificate.

**Test material only.** These keys were generated for these tests and protect nothing.

Never regenerate them to make a failing test pass. A failure means the build under test
can no longer read data an existing deployment holds, which is the thing these tests exist
to catch. The certificates expire in October 2036; replace them before then, from the
oldest build still supported.
