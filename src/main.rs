use rypt::{self, RuntimeEnvironment, UI};

fn main() {
    let env = RuntimeEnvironment::new_from_process_env();

    // 1. Parse command line. In case of an error, it'll print it using ui.print_error, so we just
    // need to exit.
    if let Ok((command, ui)) = rypt::cli::parse_command_line(env) {
        // 2. Run the command. Here we print the error using UI explicitly.
        if let Err(err) = rypt::commands::run_command(command, &ui) {
            ui.print_error(&err).ok();
            std::process::exit(1);
        }
    } else {
        std::process::exit(1);
    }
}
