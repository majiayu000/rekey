//! Broker runtime: Admin/Agent IPC surfaces, capability sessions, and the
//! fixed HTTP action executor.

pub mod audit;
pub mod error;
pub mod executor;
mod github_app;
pub mod ipc;
pub mod lifecycle;
pub mod runtime;
pub mod session;
pub mod testing;
pub mod upstream;
