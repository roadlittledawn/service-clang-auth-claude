//! Domain logic for clang-auth.
//!
//! This crate knows nothing about HTTP. It owns the data model, MongoDB access,
//! password hashing, opaque-token generation, redirect/origin validation and
//! JWT signing. The `service` crate wires these into axum handlers.

pub mod duration;
pub mod error;
pub mod keys;
pub mod model;
pub mod origin;
pub mod password;
pub mod secret;
pub mod store;

pub use error::{Error, Result};
