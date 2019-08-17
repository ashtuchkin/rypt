use failure::{Fallible, ResultExt};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use crate::{Reader, Writer};

pub type OpenReaderCb = Box<dyn FnOnce() -> Fallible<Reader>>;
pub type OpenWriterCb = Box<dyn FnOnce() -> Fallible<Writer>>;

pub enum InputStream {
    // Real file (assume we can delete it, get its size, etc).
    File { path: PathBuf },
    // File-like object in the filesystem. No assumptions except that we can open it for reading.
    FileStream { path: PathBuf },
    // Process stdin
    Stdin { open_stdin: OpenReaderCb },
}

impl InputStream {
    pub fn path(&self) -> &Path {
        match &self {
            InputStream::File { path, .. } | InputStream::FileStream { path } => &path,
            InputStream::Stdin { .. } => "(stdin)".as_ref(),
        }
    }

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
            InputStream::Stdin { open_stdin } => Ok((open_stdin()?, None)),
        }
    }

    pub fn open_with_delete_cb(
        self,
    ) -> Fallible<(Reader, Option<usize>, Option<impl FnOnce() -> Fallible<()>>)> {
        let delete_cb = match &self {
            InputStream::File { path, .. } => {
                let path = path.clone();
                Some(move || {
                    fs::remove_file(&path)
                        .with_context(|err| {
                            format!(
                                "Error deleting input file {}: {}",
                                path.to_string_lossy(),
                                err
                            )
                        })
                        .map_err(|err| err.into())
                })
            }
            InputStream::Stdin { .. } | InputStream::FileStream { .. } => None,
        };

        let (reader, filesize) = self.open()?;
        Ok((reader, filesize, delete_cb))
    }
}

impl std::fmt::Debug for InputStream {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match &self {
            InputStream::File { path } => {
                write!(f, "InputStream::File({})", path.to_string_lossy())
            }
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
    Stdout { open_stdout: OpenWriterCb },
}

impl OutputStream {
    pub fn path(&self) -> &Path {
        match &self {
            OutputStream::File { path } => &path,
            OutputStream::Stdout { .. } => "(stdout)".as_ref(),
        }
    }

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
            OutputStream::Stdout { open_stdout } => open_stdout(),
        }
    }

    pub fn open_with_delete_cb(self) -> Fallible<(Writer, Option<impl FnOnce() -> Fallible<()>>)> {
        let delete_cb = match &self {
            OutputStream::File { path } => {
                let path = path.clone();
                Some(move || {
                    fs::remove_file(&path)
                        .with_context(|err| {
                            format!(
                                "Error deleting output file {}: {}",
                                path.to_string_lossy(),
                                err
                            )
                        })
                        .map_err(|err| err.into())
                })
            }
            OutputStream::Stdout { .. } => None,
        };

        Ok((self.open()?, delete_cb))
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
