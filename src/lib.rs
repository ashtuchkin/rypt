#![warn(clippy::all)]
#![allow(dead_code, clippy::type_complexity)]
#![deny(bare_trait_objects)]

pub mod cli;
pub mod commands;
mod credentials;
mod crypto;
mod errors;
mod header;
mod header_io;
mod io_streams;
mod progress;
mod proto;
mod runtime_env;
mod shamir;
mod stream_crypto;
mod stream_pipeline;
mod terminal;
mod ui;
pub mod util;

pub use crate::runtime_env::RuntimeEnvironment;
pub use crate::ui::UI;
