#![warn(clippy::all)]
#![allow(dead_code, clippy::type_complexity)]
#![deny(bare_trait_objects)]

pub mod cli;
pub mod commands;
mod credentials;
mod crypto;
pub mod errors;
mod header;
mod header_io;
mod io_streams;
mod progress;
mod proto;
mod shamir;
mod stream_crypto;
mod stream_pipeline;
pub mod terminal;
pub mod ui;
pub mod util;

use failure::Fallible;

// Owned io::Read/Write trait objects and their factories
pub type Reader = Box<dyn std::io::Read + Send>;
pub type Writer = Box<dyn std::io::Write + Send>;
pub type ReaderFactory = Box<dyn FnOnce() -> Fallible<Reader>>;
pub type WriterFactory = Box<dyn FnOnce() -> Fallible<Writer>>;

// See https://stackoverflow.com/a/27841363 for the full list.
pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
