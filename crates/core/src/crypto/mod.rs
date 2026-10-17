//! The cryptography: at-rest encryption under `MASTER_KEY`, encrypted bundles, the
//! bytes a bundle signature covers, and the digests everything else is keyed by.

pub mod aead;
pub mod bundlesig;
pub mod digest;
pub mod encbundle;
