use failure::{Fallible, ResultExt};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use crate::{Reader, Writer};

pub enum InputStream {
    // Real file (assume we can delete it, get its size, etc).
    File {
        path: PathBuf,
        remove_on_success: bool,
    },
    // File-like object in the filesystem. No assumptions except that we can open it for reading.
    FileStream {
        path: PathBuf,
    },
    // Process stdin
    Stdin {
        reader: Reader,
    },
}

impl InputStream {
    // Open the file/stream and return corresponding Reader stream, plus file size if available.
    // Note, this consumes the InputStream due to Reader in Stdin variant not being cloneable.
    pub fn open(self) -> Fallible<(Reader, Option<usize>)> {
        match self {
            InputStream::File { path, .. } | InputStream::FileStream { path } => {
                let file = OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .with_context(|e| format!("{}: {}", path.to_string_lossy(), e))?;

                // NOTE: File-like streams report their file size as 0; we return None instead.
                let metadata = file.metadata()?;
                let filesize = if metadata.is_file() {
                    Some(metadata.len() as usize)
                } else {
                    None
                };
                Ok((Box::new(file), filesize))
            }
            InputStream::Stdin { reader } => Ok((reader, None)),
        }
    }

    pub fn path(&self) -> &Path {
        match &self {
            InputStream::File { path, .. } | InputStream::FileStream { path } => &path,
            InputStream::Stdin { .. } => "(stdin)".as_ref(),
        }
    }
}

impl std::fmt::Debug for InputStream {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match &self {
            InputStream::File {
                path,
                remove_on_success,
            } => write!(
                f,
                "InputStream::File({}, remove_on_success: {})",
                path.to_string_lossy(),
                remove_on_success
            ),
            InputStream::FileStream { path } => {
                write!(f, "InputStream::FileStream({})", path.to_string_lossy())
            }
            InputStream::Stdin { .. } => write!(f, "InputStream::Stdin"),
        }
    }
}

pub enum OutputStream {
    // Real file created by us (assume we can delete it, etc)
    File { path: PathBuf },
    // Process stdout
    Stdout { writer: Writer },
}

impl OutputStream {
    pub fn open(self) -> Fallible<Writer> {
        match self {
            OutputStream::File { path } => {
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)  // Make sure we don't overwrite existing files
                    .open(&path)
                    .with_context(|e| format!("{}: {}", path.to_string_lossy(), e))?;
                Ok(Box::new(file))
            }
            OutputStream::Stdout { writer } => Ok(writer),
        }
    }

    pub fn path(&self) -> &Path {
        match &self {
            OutputStream::File { path, .. } => &path,
            OutputStream::Stdout { .. } => "(stdout)".as_ref(),
        }
    }
}

impl std::fmt::Debug for OutputStream {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match &self {
            OutputStream::File { path } => {
                write!(f, "OutputStream::File({})", path.to_string_lossy())
            }
            OutputStream::Stdout { .. } => write!(f, "OutputStream::Stdout"),
        }
    }
}

#[derive(Debug)]
pub struct InputOutputStream {
    pub input: InputStream,
    pub output: Fallible<OutputStream>,
}

impl InputOutputStream {
    pub fn input_path(&self) -> &Path {
        self.input.path()
    }

    pub fn open_streams(
        self,
    ) -> Fallible<(
        Reader,
        Writer,
        Option<usize>,
        impl FnOnce(Fallible<()>) -> Fallible<()>,
    )> {
        let InputOutputStream { input, output } = self;
        let output = output?; // Pass any errors up immediately

        // Prepare input/output removal paths
        let on_success_remove_path = match &input {
            InputStream::File {
                path,
                remove_on_success,
            } if *remove_on_success => Some(path.clone()),
            _ => None,
        };
        let on_error_remove_path = match &output {
            OutputStream::File { path } => Some(path.clone()),
            _ => None,
        };

        // Actually open the streams.
        let (input_stream, filesize) = input.open()?;
        let output_stream = output.open()?;

        let cleanup_streams = |res| {
            match (&res, on_success_remove_path, on_error_remove_path) {
                // On success, remove input file if needed. Pass any errors up.
                (Ok(()), Some(path), _) => fs::remove_file(path)?,

                // On failure, remove output file if needed. Swallow error to keep original one.
                (Err(_), _, Some(path)) => fs::remove_file(path).unwrap_or(()),
                _ => (),
            };
            res
        };

        Ok((input_stream, output_stream, filesize, cleanup_streams))
    }
}
