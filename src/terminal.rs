// Terminal sequence to clear current line without moving cursor.
// Supported on all major terminals, including *nix, MacOS and Windows.
pub const TERMINAL_CLEAR_LINE: &str = "\x1B[2K";

#[cfg(unix)]
pub fn init_console() {
    // nothing to do
}

// In Windows we need to explicitly enable processing of terminal sequences.
#[cfg(windows)]
pub fn init_console() {
    use winapi::um::{
        consoleapi::{GetConsoleMode, SetConsoleMode},
        processenv::GetStdHandle,
        winbase::STD_ERROR_HANDLE,
        wincon::{DISABLE_NEWLINE_AUTO_RETURN, ENABLE_VIRTUAL_TERMINAL_PROCESSING},
    };

    unsafe {
        let hstderr = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0u32;
        GetConsoleMode(hstderr, &mut mode);
        // NOTE: We intentionally ignore errors here.

        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        SetConsoleMode(hstderr, mode);
    }
}

#[cfg(unix)]
pub fn is_tty(stream: &dyn std::os::unix::io::AsRawFd) -> bool {
    unsafe { libc::isatty(stream.as_raw_fd()) == 1 }
}

#[cfg(windows)]
pub fn is_tty(stream: &dyn std::os::windows::io::AsRawHandle) -> bool {
    use winapi::um::consoleapi::GetConsoleMode;
    unsafe { GetConsoleMode(stream.as_raw_handle(), &mut 0u32) != 0 }
}

// Code is taken from https://stackoverflow.com/a/1455007/325300
// and https://github.com/dtolnay/isatty/blob/master/src/lib.rs

#[cfg(unix)]
pub fn set_stdin_echo(enable: bool) {
    // NOTE: We can't use e.g. termion::input::TermRead::read_passwd because it doesn't work
    // when stdout is redirected to a file.
    use libc::{tcgetattr, tcsetattr, ECHO, STDIN_FILENO, TCSANOW};
    unsafe {
        let mut tty = std::mem::zeroed();
        tcgetattr(STDIN_FILENO, &mut tty);
        if enable {
            tty.c_lflag |= ECHO;
        } else {
            tty.c_lflag &= !ECHO;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    }
}

#[cfg(windows)]
pub fn set_stdin_echo(enable: bool) {
    use winapi::um::{
        consoleapi::{GetConsoleMode, SetConsoleMode},
        processenv::GetStdHandle,
        winbase::STD_INPUT_HANDLE,
        wincon::ENABLE_ECHO_INPUT,
    };

    unsafe {
        let hstdin = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        GetConsoleMode(hstdin, &mut mode);

        if enable {
            mode |= ENABLE_ECHO_INPUT;
        } else {
            mode &= !ENABLE_ECHO_INPUT;
        }
        SetConsoleMode(hstdin, mode);
    }
}
