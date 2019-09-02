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
mod shamir;
mod stream_crypto;
mod stream_pipeline;
pub mod terminal;
pub mod ui;
pub mod util;

pub type Reader = Box<dyn std::io::Read + Send>;
pub type Writer = Box<dyn std::io::Write + Send>;
