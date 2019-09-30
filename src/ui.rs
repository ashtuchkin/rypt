use failure::{bail, ensure, format_err, Error, Fallible};
use std::cell::{RefCell, RefMut};
use std::io::Read;
use std::rc::Rc;

use crate::terminal::{set_stdin_echo, TERMINAL_CLEAR_LINE};
use crate::util::to_hex_string;
use crate::{Reader, ReaderFactory, Writer};

const ERROR_VERBOSITY: i32 = -1;
const INTERACTIVE_VERBOSITY: i32 = -1;

// User interaction interface.
pub trait UI {
    // Initialization
    fn set_verbosity(&mut self, verbosity: i32);
    fn set_progress_enabled(&mut self, enabled: bool);

    // Environment information
    fn program_name(&self) -> &str;

    // Write/Print interface
    fn will_print(&self, verbosity: i32) -> bool;
    fn print(&self, verbosity: i32, message: &str) -> Fallible<()>;
    fn print_error(&self, err: &Error) -> Fallible<()>;
    fn println_interactive(&self, message: &str) -> Fallible<()>;
    fn println_progress(&self, verbosity: i32, message: &str, finish: bool) -> Fallible<()>;

    fn println(&self, verbosity: i32, message: &str) -> Fallible<()> {
        self.print(verbosity, &format!("{}\n", message))
    }

    // Read interface
    fn can_read(&self) -> bool;
    fn read_prompt(&self, prompt: &str) -> Fallible<String>;
    fn set_stdin_echo(&self, enable: bool);

    fn read_prompt_bool(
        &self,
        verbosity: i32,
        prompt: &str,
        default: bool,
    ) -> Fallible<Option<bool>> {
        if !self.can_read() || !self.will_print(verbosity) {
            return Ok(None);
        }

        let yn_helper = if default { "[Y/n]" } else { "[y/N]" };
        let prompt = format!("{} {}: ", prompt, yn_helper);
        loop {
            match self.read_prompt(&prompt)?.to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(Some(true)),
                "n" | "no" => return Ok(Some(false)),
                "" => return Ok(Some(default)),
                _ => {
                    self.println_interactive("Invalid input, please enter 'y' or 'n'.")?;
                }
            }
        }
    }

    fn read_password(&self, prompt: &str) -> Fallible<String> {
        ensure!(self.can_read(), "Can't read from a non-TTY input");
        self.set_stdin_echo(false);
        let res = self.read_prompt(prompt);
        self.set_stdin_echo(true);

        // With echo off we don't get the newline character from input; we need to output it ourselves.
        self.println_interactive("")?;
        res
    }
}

pub struct BasicUI {
    program_name: String,
    input: Rc<RefCell<Option<Reader>>>,
    output: RefCell<Writer>,
    input_is_tty: bool,
    output_is_tty: bool,
    verbosity: i32,
    progress_enabled: bool,
}

impl BasicUI {
    pub fn new(
        program_name: String,
        input: Reader,
        input_is_tty: bool,
        output: Writer,
        output_is_tty: bool,
    ) -> BasicUI {
        BasicUI {
            program_name,
            input: Rc::new(RefCell::new(Some(input))),
            input_is_tty,
            output: RefCell::new(output),
            output_is_tty,
            verbosity: 0,
            progress_enabled: true,
        }
    }

    // Create a function that extracts input stream from this struct, returning it to the caller.
    // After returned function is called, this struct loses input stream and with it the ability to
    // prompt user for input/passwords.
    pub fn input_stream_extractor(&mut self) -> ReaderFactory {
        let input = Rc::clone(&self.input);
        Box::new(move || Ok(input.borrow_mut().take().unwrap()))
    }
}

impl UI for BasicUI {
    fn set_verbosity(&mut self, verbosity: i32) {
        self.verbosity = verbosity;
    }

    fn set_progress_enabled(&mut self, enabled: bool) {
        self.progress_enabled = enabled;
    }

    fn program_name(&self) -> &str {
        &self.program_name
    }

    // Write interface
    fn will_print(&self, verbosity: i32) -> bool {
        verbosity <= self.verbosity
    }

    fn print(&self, verbosity: i32, message: &str) -> Fallible<()> {
        if self.will_print(verbosity) {
            self.output.borrow_mut().write_all(message.as_bytes())?;
        }
        Ok(())
    }

    fn print_error(&self, err: &Error) -> Fallible<()> {
        if self.will_print(ERROR_VERBOSITY) {
            writeln!(self.output.borrow_mut(), "{}: {}", self.program_name, err)?;
        }
        Ok(())
    }

    fn println_interactive(&self, message: &str) -> Fallible<()> {
        if self.will_print(INTERACTIVE_VERBOSITY) {
            writeln!(self.output.borrow_mut(), "{}", message)?;
        }
        Ok(())
    }

    fn println_progress(&self, verbosity: i32, message: &str, finish: bool) -> Fallible<()> {
        if self.progress_enabled {
            let last_char = if finish { "\n" } else { "\r" };
            let message = format!("{}{}{}", TERMINAL_CLEAR_LINE, message, last_char);
            self.print(verbosity, &message)?;
        }
        Ok(())
    }

    // Read interface

    fn can_read(&self) -> bool {
        self.input.borrow().is_some()
            && self.input_is_tty
            && self.output_is_tty
            && self.will_print(INTERACTIVE_VERBOSITY)
    }

    fn read_prompt(&self, prompt: &str) -> Fallible<String> {
        ensure!(self.can_read(), "Can't read from a non-TTY input");
        let mut output = self.output.borrow_mut();
        let mut input = RefMut::map(self.input.borrow_mut(), |i| i.as_mut().unwrap());
        write!(output, "{}", prompt)?;

        // Read from stdin byte-by-byte and convert them to utf8 characters, stopping at '\n'.
        let mut char_bytes = vec![];
        let mut res = String::new();
        for byte in input.by_ref().bytes() {
            char_bytes.push(byte?);
            match std::str::from_utf8(&char_bytes) {
                Ok(valid_char) => {
                    match valid_char {
                        "\n" => {
                            if res.ends_with('\r') {
                                res.pop(); // Handle Windows CRLF.
                            }
                            return Ok(res);
                        }
                        valid_char => res.push_str(valid_char),
                    }
                    char_bytes.clear();
                }
                Err(utf_err) => match utf_err.error_len() {
                    None => (), // Incomplete character - get more bytes.
                    Some(_) => bail!(
                        "Error reading from stdin: Non-UTF8 byte sequence encountered: {}",
                        to_hex_string(char_bytes)
                    ),
                },
            }
        }
        Err(format_err!("Error reading from stdin: EOF"))
    }

    fn set_stdin_echo(&self, enable: bool) {
        set_stdin_echo(enable);
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, PartialEq, Clone, Copy)]
    pub enum PrintType {
        Log { verbosity: i32 },
        Error,
        Interactive,
        Progress { verbosity: i32, finish: bool },
    }

    #[derive(Default)]
    pub struct TestUI {
        pub prompt_replies: RefCell<VecDeque<(Option<String>, Result<String, Error>)>>,
        pub printed_lines: RefCell<VecDeque<(PrintType, String, bool)>>,
    }

    impl TestUI {
        pub fn new() -> TestUI {
            TestUI {
                ..Default::default()
            }
        }

        pub fn expect_prompt(
            self,
            matcher: impl AsRef<str>,
            reply: Result<impl AsRef<str>, Error>,
        ) -> Self {
            self.prompt_replies.borrow_mut().push_back((
                Some(matcher.as_ref().to_string()),
                reply.map(|s| s.as_ref().to_string()),
            ));
            self
        }

        pub fn expect_all_prompts_asked(&self) {
            assert_eq!(self.prompt_replies.borrow_mut().len(), 0);
        }

        fn append_printed_lines(&self, typ: PrintType, message: impl AsRef<str>) -> Fallible<()> {
            let message = message.as_ref();
            let lines = message.lines().collect::<Vec<_>>();
            let lines_len = lines.len();
            let mut line_tuples = lines.into_iter().enumerate().map(|(idx, line)| {
                let line_finished = idx < lines_len - 1 || message.ends_with('\n');
                (typ, line.to_string(), line_finished)
            });

            let mut printed_lines = self.printed_lines.borrow_mut();

            // Append to last line if it has the same type
            if let Some((last_typ, last_line, last_line_finished)) = printed_lines.back_mut() {
                if *last_typ == typ && !*last_line_finished {
                    if let Some((_, line, finished)) = line_tuples.next() {
                        last_line.push_str(&line);
                        *last_line_finished = finished;
                    }
                }
            }

            printed_lines.extend(line_tuples);
            Ok(())
        }
    }

    impl UI for TestUI {
        fn set_verbosity(&mut self, _verbosity: i32) {}
        fn set_progress_enabled(&mut self, _enabled: bool) {}

        fn program_name(&self) -> &str {
            "rypt"
        }

        // Write interface
        fn will_print(&self, _verbosity: i32) -> bool {
            true
        }

        fn print(&self, verbosity: i32, message: &str) -> Fallible<()> {
            self.append_printed_lines(PrintType::Log { verbosity }, message)
        }

        fn print_error(&self, err: &Error) -> Result<(), Error> {
            self.append_printed_lines(PrintType::Error, &format!("{}", err))
        }

        fn println_interactive(&self, message: &str) -> Result<(), Error> {
            self.append_printed_lines(PrintType::Interactive, message)
        }

        fn println_progress(&self, verbosity: i32, message: &str, finish: bool) -> Fallible<()> {
            self.append_printed_lines(PrintType::Progress { verbosity, finish }, message)
        }

        // Read interface
        fn can_read(&self) -> bool {
            true
        }

        fn read_prompt(&self, prompt: &str) -> Result<String, Error> {
            let (matcher, reply) = self
                .prompt_replies
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("Unexpected prompt in TestUI: '{}'", prompt));

            if let Some(matcher) = matcher {
                assert!(
                    prompt.contains(&matcher),
                    "Unexpected prompt in TestUI: '{}', was looking for '{}'",
                    prompt,
                    matcher
                );
            }

            reply
        }

        fn set_stdin_echo(&self, _enable: bool) {}
    }
}
