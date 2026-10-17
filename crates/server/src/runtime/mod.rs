//! Starting and running the process: configuration, the shutdown signal, startup fixes
//! to stored tenants, and the periodic housekeeping sweep.

pub mod config;
pub mod env_file;
pub mod housekeeping;
pub mod shutdown;
pub mod tenant_setup;
