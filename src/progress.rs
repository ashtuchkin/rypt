use crate::{util, Options, RuntimeEnvironment};
use std::collections::VecDeque;
use std::io::Write;
use std::iter::FromIterator;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn print_file_progress_header(
    input_path: &Path,
    opts: &Options,
    env: &RuntimeEnvironment,
    file_idx: usize,
    total_files: usize,
) {
    if opts.verbose > 0 {
        let mut path = input_path.to_string_lossy();
        if path == "-" {
            path = "(stdin)".into();
        }
        let mut stderr = env.stderr.borrow_mut();
        writeln!(stderr, "{} ({}/{})", path, file_idx + 1, total_files).ok();
    }
}

const PRINT_PERIOD: Duration = Duration::from_millis(100);
const SPEED_CALC_PERIOD: Duration = Duration::from_secs(10); // Calculate speed over the last 10 seconds
const KEEP_STAMPS_COUNT: usize =
    (SPEED_CALC_PERIOD.as_millis() / PRINT_PERIOD.as_millis()) as usize;

pub struct ProgressPrinter<'a> {
    start_time: Instant,
    stamps: VecDeque<(Instant, usize)>,
    last_printed_period: u64,
    output: &'a mut Write,
    do_print: bool, // TODO: Avoid creation of the progress printer if we're not printing.
}

impl<'a> ProgressPrinter<'a> {
    pub fn new(output: &mut Write, do_print: bool) -> ProgressPrinter {
        let now = Instant::now();
        ProgressPrinter {
            start_time: now,
            stamps: VecDeque::from_iter(vec![(now, 0usize)].into_iter()),
            last_printed_period: 0,
            output,
            do_print,
        }
    }

    pub fn print_progress(&mut self, written_bytes: usize) {
        if !self.do_print {
            return;
        }
        let now = Instant::now();

        // 1. Print no more than once per PRINT_PERIOD
        let period_id = ((now - self.start_time).as_millis() / PRINT_PERIOD.as_millis()) as u64;
        if period_id == self.last_printed_period {
            return;
        }
        self.last_printed_period = period_id;

        // 2. Store precise timing for several last counts.
        self.stamps.push_back((now, written_bytes));
        if self.stamps.len() > KEEP_STAMPS_COUNT {
            self.stamps.pop_front();
        }

        // 3. Calculate average over the last KEEP_STAMPS_COUNT periods.
        let (end_period_time, end_period_progress) = *self.stamps.back().unwrap();
        let (start_period_time, start_period_progress) = *self.stamps.front().unwrap();
        let delta_time = (end_period_time - start_period_time).as_millis() as usize;
        let delta_progress = end_period_progress - start_period_progress;
        if delta_time > 0 {
            let speed = delta_progress * 1000 / delta_time;
            write!(
                self.output,
                "\r{}    Processed: {}, {}/s, Elapsed time: {}",
                termion::clear::CurrentLine,
                util::human_file_size(end_period_progress),
                util::human_file_size(speed),
                util::human_duration(Instant::now() - self.start_time),
            )
            .ok();
        }
    }
}

impl<'a> Drop for ProgressPrinter<'a> {
    fn drop(&mut self) {
        if self.last_printed_period > 0 {
            writeln!(self.output).ok();
        }
    }
}
