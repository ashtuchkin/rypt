use crate::cli::define_options;
use crate::io_streams::OutputStream;
use failure::Fallible;

// See https://stackoverflow.com/a/27841363 for the full list.
const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn print_help(output: OutputStream, program_name: &str) -> Fallible<()> {
    let options = define_options();
    let mut stdout = output.open()?;
    writeln!(
        stdout,
        "\
Usage: {} [OPTION].. [FILE]..
Encrypt/decrypt FILE-s

{}

With no FILE, or when FILE is '-', read standard input and write to standard output.

Home page and documentation: <https://github.com/ashtuchkin/rypt>",
        program_name,
        options.usage("").trim()
    )?;
    Ok(())
}

pub fn print_version(output: OutputStream) -> Fallible<()> {
    let mut stdout = output.open()?;
    writeln!(stdout, "{} {}", PKG_NAME, PKG_VERSION)?;
    let libsodium_version =
        unsafe { std::ffi::CStr::from_ptr(libsodium_sys::sodium_version_string()) };
    writeln!(stdout, "libsodium {}", libsodium_version.to_str()?)?;
    Ok(())
}
