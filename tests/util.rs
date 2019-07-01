use failure::{bail, Fallible};
use rand::distributions::Distribution;
use rand::{Rng, RngCore};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

pub fn random_str(mut rng: &mut rand::RngCore, len: usize) -> String {
    rand::distributions::Alphanumeric
        .sample_iter(&mut rng)
        .take(len)
        .collect()
}

pub fn random_bytes(rng: &mut rand::RngCore, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill(bytes.as_mut_slice());
    bytes
}

pub fn create_temp_file(rng: &mut RngCore, extension: &str) -> Fallible<(PathBuf, Vec<u8>)> {
    let temp_file = env::temp_dir()
        .join(random_str(rng, 10))
        .with_extension(extension);
    let contents = random_bytes(rng, 10_000);
    fs::write(&temp_file, &contents)?;
    Ok((temp_file, contents))
}

pub fn main_binary_path() -> Fallible<PathBuf> {
    // Assume current function is called from an integration test, which itself is compiled to a
    // binary in the 'deps' subfolder of the folder that contains the main binary.
    let mut path = std::env::current_exe()?;
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }

    let binary_path = path.join(format!(
        "{}{}",
        env!("CARGO_PKG_NAME"),
        std::env::consts::EXE_SUFFIX
    ));

    if !binary_path.is_file() {
        bail!("Main binary not found: {}", binary_path.to_string_lossy());
    }

    Ok(binary_path)
}

pub fn main_cmd<I>(args: I) -> Fallible<Command>
where
    I: IntoIterator,
    I::Item: AsRef<std::ffi::OsStr>,
{
    let mut cmd = Command::new(main_binary_path()?);
    cmd.args(args);
    Ok(cmd)
}

// As stdin only can read from File, let's create a temp file with provided contents, then feed it
// to the stdin. File will be automatically deleted after close.
pub fn file_from_buf(val: impl AsRef<[u8]>) -> Fallible<File> {
    let mut file = tempfile::tempfile()?;
    file.write_all(val.as_ref())?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

pub trait CommandExt {
    fn stdin_buf(&mut self, val: impl AsRef<[u8]>) -> Fallible<&mut Self>;
}

impl CommandExt for Command {
    fn stdin_buf(&mut self, val: impl AsRef<[u8]>) -> Fallible<&mut Self> {
        Ok(self.stdin(file_from_buf(val)?))
    }
}
