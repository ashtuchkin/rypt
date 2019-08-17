use rypt::{self, RuntimeEnvironment};

fn main() {
    let runtime_env = RuntimeEnvironment::new_from_process_env();

    let res = rypt::run(runtime_env);

    if let Err(_err) = res {
        //        let mut stderr = runtime_env.stderr.borrow_mut();
        //        match err.downcast::<EarlyTerminationError>() {
        //            Ok(_) => (), // Don't print anything in case of early termination
        //            Err(err) => writeln!(stderr, "{}: {}", rypt::PKG_NAME, err).unwrap_or(()),
        //        }
        std::process::exit(1);
    }
}
