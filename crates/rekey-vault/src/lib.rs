//! First-party Credential Authority: encrypted storage, key hierarchy,
//! offline bootstrap, and the AuthorityWorker state machine.

pub mod authority;
pub mod bootstrap;
pub mod command;
pub mod crypto;
pub mod durable;
pub mod error;
pub mod model;
pub mod secret;
pub mod store;

pub use error::AuthorityError;
pub mod convert;
pub mod handle;
pub mod paths;
