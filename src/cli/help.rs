use crate::cli::define_options;
use crate::{RuntimeEnvironment, PKG_NAME, PKG_VERSION};
use failure::Fallible;

pub fn print_help(env: &RuntimeEnvironment) -> Fallible<()> {
    let options = define_options();
    let mut stdout = env.stdout.replace(Box::new(std::io::sink()));
    writeln!(
        stdout,
        "\
Usage: {} [OPTION].. [FILE]..
Encrypt/decrypt FILE-s

{}

With no FILE, or when FILE is '-', read standard input and write to standard output.

Home page and documentation: <https://github.com/ashtuchkin/rypt>",
        env.program_name.to_string_lossy(),
        options.usage("").trim()
    )?;
    Ok(())
}

pub fn print_version(env: &RuntimeEnvironment) -> Fallible<()> {
    let mut stdout = env.stdout.replace(Box::new(std::io::sink()));
    writeln!(stdout, "{} {}", PKG_NAME, PKG_VERSION)?;
    let libsodium_version =
        unsafe { std::ffi::CStr::from_ptr(libsodium_sys::sodium_version_string()) };
    writeln!(stdout, "libsodium {}", libsodium_version.to_str()?)?;
    Ok(())
}
