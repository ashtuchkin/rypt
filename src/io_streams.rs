use failure::{ensure, Fallible, ResultExt};
use std::fs::{self, Metadata, OpenOptions};
use std::path::{Path, PathBuf};

use crate::util;
use crate::{Reader, ReaderFactory, Writer, WriterFactory};

pub enum InputStream {
    // Real file (assume we can delete it, get its size, etc).
    File { path: PathBuf },
    // File-like object in the filesystem. No assumptions except that we can open it for reading.
    FileStream { path: PathBuf },
    // Process stdin
    Stdin { open_stdin: ReaderFactory },
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
    pub fn open(self, force: bool) -> Fallible<(Reader, Option<usize>)> {
        fn open_file(path: &Path) -> Fallible<(Reader, Metadata)> {
            let file = OpenOptions::new()
                .read(true)
                .open(&path)
                .with_context(|e| format!("Error opening '{}': {}", path.to_string_lossy(), e))?;

            let metadata = fs::symlink_metadata(path)?;
            ensure!(!metadata.is_dir(), "Can't encrypt/decrypt a directory.");

            Ok((Box::new(file), metadata))
        }

        match self {
            InputStream::File { path } => {
                let (stream, metadata) = open_file(&path)?;

                // Check we have a real file, not a symlink or a hardlink.
                if !force {
                    let file_type = metadata.file_type();
                    ensure!(!file_type.is_symlink(), "Can't encrypt/decrypt a symlink. Use streaming mode (-s) or force (-f) to override.");
                    ensure!(util::num_hardlinks(&metadata) == 1, "Can't encrypt/decrypt a file with hard links. Use streaming mode (-s) or force (-f) to override.");
                    ensure!(file_type.is_file(), "Can't encrypt/decrypt non-regular file. Use streaming mode (-s) or force (-f) to override.");
                }

                Ok((stream, Some(metadata.len() as usize)))
            }
            InputStream::FileStream { path } => {
                let (stream, metadata) = open_file(&path)?;

                // NOTE: File-like streams report their file size as 0; we return None instead.
                let filesize = Some(metadata.len() as usize).filter(|&len| len > 0);
                Ok((stream, filesize))
            }
            InputStream::Stdin { open_stdin } => {
                let stream = open_stdin()?;
                Ok((stream, None))
            }
        }
    }

    pub fn open_with_cleanup_cb(
        self,
        force: bool,
    ) -> Fallible<(Reader, Option<usize>, Option<impl FnOnce() -> Fallible<()>>)> {
        let cleanup_cb_opt = match &self {
            InputStream::File { path, .. } => {
                let path = path.clone();
                Some(move || {
                    let res = fs::remove_file(&path).with_context(|err| {
                        format!("Error deleting '{}': {}", path.to_string_lossy(), err)
                    });

                    // Ignore error if forced.
                    if !force {
                        res?
                    }
                    Ok(())
                })
            }
            InputStream::Stdin { .. } | InputStream::FileStream { .. } => None,
        };

        let (reader, filesize) = self.open(force)?;
        Ok((reader, filesize, cleanup_cb_opt))
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
    Stdout { open_stdout: WriterFactory },
}

impl OutputStream {
    pub fn path(&self) -> &Path {
        match &self {
            OutputStream::File { path } => &path,
            OutputStream::Stdout { .. } => "(stdout)".as_ref(),
        }
    }

    pub fn open(self, force: bool) -> Fallible<Writer> {
        match self {
            OutputStream::File { path } => {
                let mut open_opts = OpenOptions::new();
                open_opts.write(true);

                if !force {
                    // Make sure we don't overwrite existing files
                    open_opts.create_new(true);
                } else {
                    open_opts.truncate(true);
                    open_opts.create(true);
                }

                let file = open_opts.open(&path).with_context(|e| {
                    format!("Error creating '{}': {}", path.to_string_lossy(), e)
                })?;

                Ok(Box::new(file))
            }
            OutputStream::Stdout { open_stdout } => open_stdout(),
        }
    }

    pub fn open_with_cleanup_cb(
        self,
        force: bool,
    ) -> Fallible<(Writer, Option<impl FnOnce() -> Fallible<()>>)> {
        let cleanup_cb_opt = match &self {
            OutputStream::File { path } => {
                let path = path.clone();
                Some(move || {
                    let res = fs::remove_file(&path).with_context(|err| {
                        format!("Error deleting '{}': {}", path.to_string_lossy(), err)
                    });
                    // Ignore error if forced.
                    if !force {
                        res?
                    }
                    Ok(())
                })
            }
            OutputStream::Stdout { .. } => None,
        };

        Ok((self.open(force)?, cleanup_cb_opt))
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
