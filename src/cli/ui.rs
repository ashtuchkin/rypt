use failure::{bail, ensure, Error, Fallible};
use std::cell::{RefCell, RefMut};

use crate::terminal::set_stdin_echo;
use crate::{Reader, Writer};
use std::fmt::Display;
use std::rc::Rc;

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
        program_name: &str,
        input: Reader,
        input_is_tty: bool,
        output: Writer,
        output_is_tty: bool,
    ) -> BasicUI {
        BasicUI {
            program_name: program_name.to_string(),
            input: Rc::new(RefCell::new(Some(input))),
            input_is_tty,
            output: RefCell::new(output),
            output_is_tty,
            verbose: 0,
        }
    }

    pub fn set_verbosity(&mut self, verbose: i32) {
        self.verbose = verbose;
    }

    pub fn ref_input_opt(&self) -> Rc<RefCell<Option<Reader>>> {
        Rc::clone(&self.input)
    }

    // Write interface

    pub fn will_print(&self, verbosity: i32) -> bool {
        verbosity <= self.verbose
    }

    pub fn print_error(&self, err: &Error) -> Fallible<()> {
        writeln!(self.output.borrow_mut(), "{}: {}", self.program_name, err)?;
        Ok(())
    }

    pub fn print_interactive(&self, message: impl Display) -> Fallible<()> {
        writeln!(self.output.borrow_mut(), "{}", message)?;
        Ok(())
    }

    pub fn print(&self, verbosity: i32, message: impl Display) -> Fallible<()> {
        if self.will_print(verbosity) {
            write!(self.output.borrow_mut(), "{}", message)?;
        }
        Ok(())
    }

    pub fn println(&self, verbosity: i32, message: impl Display) -> Fallible<()> {
        if self.will_print(verbosity) {
            writeln!(self.output.borrow_mut(), "{}", message)?;
        }
        Ok(())
    }

    // Read interface

    pub fn can_read(&self) -> bool {
        self.input.borrow().is_some() && self.input_is_tty && self.output_is_tty
    }

    pub fn read_prompt(&self, prompt: impl Display) -> Fallible<String> {
        ensure!(self.can_read(), "Can't read from a non-TTY input");
        let mut output = self.output.borrow_mut();
        let mut input = RefMut::map(self.input.borrow_mut(), |i| i.as_mut().unwrap());
        write!(output, "{}", prompt)?;

        let mut bytes: Vec<u8> = vec![];
        let mut byte = 0u8;
        loop {
            match input.read(std::slice::from_mut(&mut byte)) {
                Ok(0) => bail!("Error reading from stdin: EOF"),
                Ok(1) => match byte {
                    b'\n' | b'\r' => break,
                    b => bytes.push(b),
                },
                Ok(_) => unreachable!(),
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(String::from_utf8(bytes)?)
    }

    pub fn read_prompt_bool(&self, prompt: impl Display, default: bool) -> Fallible<bool> {
        let yn_helper = if default { "[Y/n]" } else { "[y/N]" };
        let prompt = format!("{} {}: ", prompt, yn_helper);
        loop {
            match self.read_prompt(&prompt)?.to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                "" => return Ok(default),
                _ => {
                    self.print_interactive("Invalid input, please enter 'y' or 'n'.")?;
                }
            }
        }
    }

    pub fn read_password(&self, prompt: impl Display) -> Fallible<String> {
        ensure!(self.can_read(), "Can't read from a non-TTY input");
        set_stdin_echo(false);
        let res = self.read_prompt(prompt);
        set_stdin_echo(true);

        // With echo off we don't get the newline character from input; we need to output it ourselves.
        writeln!(self.output.borrow_mut()).ok();
        res
    }
}
