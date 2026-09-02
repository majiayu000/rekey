//! Pure domain models, invariants, and typed errors for rekey v2.
//!
//! This crate performs no IO and must not depend on Tokio, HTTP, SQLite,
//! environment variables, or the filesystem.

pub mod action;
pub mod audit;
pub mod authorization;
pub mod capability;
pub mod credential;
pub mod error;
pub mod ids;
pub mod ipc;
pub mod time;

pub use error::DomainError;
pub use time::Timestamp;
