use failure::{bail, ensure, format_err, Error, Fallible};
use std::cell::{RefCell, RefMut};
use std::io::Read;
use std::rc::Rc;

use crate::terminal::{set_stdin_echo, TERMINAL_CLEAR_LINE};
use crate::util::to_hex_string;
use crate::{Reader, Writer};

// User interaction interface.
pub trait UI {
    // Initialization
    fn set_verbosity(&mut self, verbosity: i32);

    // Environment information
    fn program_name(&self) -> &'_ str;

    // Write/Print interface
    fn will_print(&self, verbosity: i32) -> bool;
    fn print(&self, verbosity: i32, message: &str) -> Fallible<()>;
    fn print_error(&self, err: &Error) -> Fallible<()>;
    fn println_interactive(&self, message: &str) -> Fallible<()>;

    fn println(&self, verbosity: i32, message: &str) -> Fallible<()> {
        self.print(verbosity, &format!("{}\n", message))
    }

    fn print_overwrite_line(&self, verbosity: i32, message: &str) -> Fallible<()> {
        self.print(verbosity, &format!("{}{}\r", TERMINAL_CLEAR_LINE, message))
    }

    // Read interface
    fn can_read(&self) -> bool;
    fn read_prompt(&self, prompt: &str) -> Fallible<String>;
    fn set_stdin_echo(&self, enable: bool);

    fn read_prompt_bool(&self, prompt: &str, default: bool) -> Fallible<bool> {
        let yn_helper = if default { "[Y/n]" } else { "[y/N]" };
        let prompt = format!("{} {}: ", prompt, yn_helper);
        loop {
            match self.read_prompt(&prompt)?.to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                "" => return Ok(default),
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
    verbose: i32,
}

impl BasicUI {
    pub fn from_streams(
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
            verbose: 0,
        }
    }

    pub fn ref_input_opt(&mut self) -> Rc<RefCell<Option<Reader>>> {
        Rc::clone(&self.input)
    }
}

impl UI for BasicUI {
    fn set_verbosity(&mut self, verbose: i32) {
        self.verbose = verbose;
    }

    fn program_name(&self) -> &'_ str {
        &self.program_name
    }

    // Write interface
    fn will_print(&self, verbosity: i32) -> bool {
        verbosity <= self.verbose
    }

    fn print(&self, verbosity: i32, message: &str) -> Fallible<()> {
        if self.will_print(verbosity) {
            self.output.borrow_mut().write_all(message.as_bytes())?;
        }
        Ok(())
    }

    fn print_error(&self, err: &Error) -> Fallible<()> {
        writeln!(self.output.borrow_mut(), "{}: {}", self.program_name, err)?;
        Ok(())
    }

    fn println_interactive(&self, message: &str) -> Fallible<()> {
        writeln!(self.output.borrow_mut(), "{}", message)?;
        Ok(())
    }

    // Read interface

    fn can_read(&self) -> bool {
        self.input.borrow().is_some() && self.input_is_tty && self.output_is_tty
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
