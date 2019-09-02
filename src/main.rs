use rypt::{
    self,
    terminal::{init_console, is_tty},
    ui::{BasicUI, UI},
    Reader, Writer,
};

fn main() {
    // Some OS-s need special initialization code for console to behave correctly.
    init_console();

    // Grab all stdio streams, check if whether they are tty and convert to Reader/Writer interface.
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let stdin_is_tty = is_tty(&stdin);
    let stdout_is_tty = is_tty(&stdout);
    let stderr_is_tty = is_tty(&stderr);
    let stdin: Reader = Box::new(stdin);
    let stdout: Writer = Box::new(stdout);
    let stderr: Writer = Box::new(stderr);

    // Get program name and command line args
    let mut args = std::env::args();
    let program_name = args.next().unwrap_or_else(|| "rypt".into());
    let cmdline_args: Vec<String> = args.collect();

    // Create a terminal UI structure that is responsible for printing messages/errors and prompting
    // user for information like passwords. Initially it owns both Stdin and Stderr, but later
    // Stdin can be taken away to be used as an encryption/decryption input.
    let mut ui = BasicUI::new(program_name, stdin, stdin_is_tty, stderr, stderr_is_tty);

    // Create callbacks that return stdin/stdout streams when called. They can only be called once.
    // Note that as UI initially owns Stdin, `open_stdin` will transfer the ownership of this stream
    // to the caller. Stdout is exclusively used for data output, so it's simply moved to the closure.
    let open_stdin = ui.input_stream_extractor();
    let open_stdout = Box::new(move || Ok(stdout));

    // Parse command line arguments to create a Command struct, which contains all the information
    // needed to start execution, including, possibly the open_stdin/stdout callbacks.
    let res = rypt::cli::parse_command_line(
        &cmdline_args,
        open_stdin,
        stdin_is_tty,
        open_stdout,
        stdout_is_tty,
        &mut ui,
    );

    // Execute the command.
    let res = res.and_then(|command| rypt::commands::run_command(command, &ui));

    // Print error, if any.
    res.unwrap_or_else(|err| {
        ui.print_error(&err).ok();
        std::process::exit(1);
    });
}
