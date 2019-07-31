use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::io;

pub type Reader = Box<io::Read + Send>;
pub type Writer = Box<io::Write + Send>;

pub struct RuntimeEnvironment {
    pub program_name: OsString,
    pub cmdline_args: Vec<OsString>,
    pub env_vars: HashMap<OsString, OsString>,
    pub stdin: RefCell<Reader>,
    pub stdout: RefCell<Writer>,
    pub stderr: RefCell<Writer>,
    pub stdin_is_tty: bool,
    pub stdout_is_tty: bool,
    pub stderr_is_tty: bool,
}

impl RuntimeEnvironment {
    pub fn new_from_process_env() -> RuntimeEnvironment {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        let stdin_is_tty = termion::is_tty(&stdin);
        let stdout_is_tty = termion::is_tty(&stdout);
        let stderr_is_tty = termion::is_tty(&stderr);
        let mut cmdline_args: Vec<OsString> = env::args_os().collect();
        let program_name = if !cmdline_args.is_empty() {
            cmdline_args.remove(0)
        } else {
            "".into()
        };

        RuntimeEnvironment {
            program_name,
            cmdline_args,
            env_vars: env::vars_os().collect(),
            stdin: RefCell::new(Box::new(stdin)),
            stdout: RefCell::new(Box::new(stdout)),
            stderr: RefCell::new(Box::new(stderr)),
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
            env_vars: HashMap::new(),
            stdin: RefCell::new(Box::new(io::empty())),
            stdout: RefCell::new(Box::new(io::sink())),
            stderr: RefCell::new(Box::new(io::sink())),
            stdin_is_tty: true,
            stdout_is_tty: true,
            stderr_is_tty: true,
        }
    }
}
