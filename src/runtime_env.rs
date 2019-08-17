use crate::terminal::is_tty;
use std::env;
use std::io;

pub type Reader = Box<dyn io::Read + Send>;
pub type Writer = Box<dyn io::Write + Send>;

pub struct RuntimeEnvironment {
    pub program_name: String,
    pub cmdline_args: Vec<String>,
    pub stdin: Reader,
    pub stdout: Writer,
    pub stderr: Writer,
    pub stdin_is_tty: bool,
    pub stdout_is_tty: bool,
    pub stderr_is_tty: bool,
}

impl RuntimeEnvironment {
    pub fn new_from_process_env() -> RuntimeEnvironment {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        let stdin_is_tty = is_tty(&stdin);
        let stdout_is_tty = is_tty(&stdout);
        let stderr_is_tty = is_tty(&stderr);
        let mut cmdline_args: Vec<String> = env::args().collect();
        let program_name = if !cmdline_args.is_empty() {
            cmdline_args.remove(0)
        } else {
            "".into()
        };

        RuntimeEnvironment {
            program_name,
            cmdline_args,
            stdin: Box::new(stdin),
            stdout: Box::new(stdout),
            stderr: Box::new(stderr),
            stdin_is_tty,
            stdout_is_tty,
            stderr_is_tty,
        }
    }
}

impl Default for RuntimeEnvironment {
    fn default() -> Self {
        RuntimeEnvironment {
            program_name: "rypt".into(),
            cmdline_args: vec![],
            stdin: Box::new(io::empty()),
            stdout: Box::new(io::sink()),
            stderr: Box::new(io::sink()),
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
        }
    }
}
