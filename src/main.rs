use rypt::{
    self,
    terminal::{init_console, is_tty},
    ui::{BasicUI, UI},
    Reader, Writer,
};

fn main() {
    init_console();

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let stdin_is_tty = is_tty(&stdin);
    let stdout_is_tty = is_tty(&stdout);
    let stderr_is_tty = is_tty(&stderr);
    let stdin: Reader = Box::new(stdin);
    let stdout: Writer = Box::new(stdout);
    let stderr: Writer = Box::new(stderr);

    let mut args = std::env::args();
    let program_name = args.next().unwrap_or_else(|| "rypt".into());
    let cmdline_args: Vec<String> = args.collect();

    let mut ui = BasicUI::from_streams(program_name, stdin, stdin_is_tty, stderr, stderr_is_tty);

    // Callbacks that return stdin/stdout when called. Used to create InputStream/OutputStream.
    // We have a rather complicated structure for stdin to allow using it both from UI and as an
    // input for encryption. When open_stdin is called, the stream ownership is transferred from UI
    // to InputStream.
    let ui_stdin = ui.ref_input_opt();
    let open_stdin = Box::new(move || Ok(ui_stdin.borrow_mut().take().unwrap()));
    let open_stdout = Box::new(move || Ok(stdout));

    rypt::cli::parse_command_line(
        &cmdline_args,
        open_stdin,
        stdin_is_tty,
        open_stdout,
        stdout_is_tty,
        &mut ui,
    )
    .and_then(|command| rypt::commands::run_command(command, &ui))
    .unwrap_or_else(|err| {
        ui.print_error(&err).ok();
        std::process::exit(1);
    });
}
