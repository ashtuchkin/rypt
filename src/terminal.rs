// Terminal sequence to clear current line without moving cursor.
// Supported on all major terminals, including *nix, MacOS and Windows.
pub const TERMINAL_CLEAR_LINE: &str = "\x1B[2K";

#[cfg(unix)]
pub fn is_tty<T: std::os::unix::io::AsRawFd>(stream: &T) -> bool {
    unsafe { libc::isatty(stream.as_raw_fd()) == 1 }
}

// TODO: Support windows platform using solution from https://stackoverflow.com/a/1455007/325300
// similarly to https://github.com/dtolnay/isatty/blob/master/src/lib.rs

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
