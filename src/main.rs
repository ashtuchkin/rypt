use rypt::{self, RuntimeEnvironment};

fn main() {
    let runtime_env = RuntimeEnvironment::new_from_process_env();
    let exit_code = rypt::run(&runtime_env);
    std::process::exit(exit_code);
}
