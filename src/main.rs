use rypt::{self, RuntimeEnvironment};

fn main() {
    let runtime_env = RuntimeEnvironment::new_from_process_env();
    if let Err(err) = rypt::run(&runtime_env) {
        let mut stderr = runtime_env.stderr.borrow_mut();
        writeln!(stderr, "{}: {}", rypt::PKG_NAME, err).ok();
        std::process::exit(1);
    }
}
