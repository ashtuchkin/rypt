use std::collections::VecDeque;
use std::io::Write;
use std::iter::FromIterator;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{util, Writer};

const PRINT_PERIOD: Duration = Duration::from_millis(100);
const SPEED_CALC_PERIOD: Duration = Duration::from_secs(10); // Calculate speed over the last 10 seconds
const KEEP_STAMPS_COUNT: usize =
    (SPEED_CALC_PERIOD.as_millis() / PRINT_PERIOD.as_millis()) as usize;

pub struct ProgressPrinter<'a> {
    output: &'a mut Writer,
    start_time: Instant,
    stamps: VecDeque<(Instant, usize)>,
    last_printed_period: i64,
    printed_at_least_once: bool,
    filesize: Option<usize>,
    verbose: i32,
}

impl<'a> ProgressPrinter<'a> {
    pub fn new(output: &'a mut Writer, verbose: i32) -> ProgressPrinter<'a> {
        let now = Instant::now();
        ProgressPrinter {
            output,
            start_time: now,
            stamps: VecDeque::from_iter(vec![(now, 0usize)].into_iter()),
            last_printed_period: -1,
            filesize: None,
            printed_at_least_once: false,
            verbose,
        }
    }

    pub fn set_filesize(&mut self, filesize: Option<usize>) {
        self.filesize = filesize;
    }

    pub fn print_file_header(&mut self, input_path: &Path, file_idx: usize, total_files: usize) {
        if self.verbose <= 0 {
            return;
        }
        let mut path = input_path.to_string_lossy();
        if path == "-" {
            if total_files == 1 {
                return; // Don't print header if we only have one stdin input.
            }
            path = "(stdin)".into();
        }
        writeln!(self.output, "{} ({}/{})", path, file_idx + 1, total_files).ok();
    }

    pub fn print_progress(&mut self, written_bytes: usize) {
        if self.verbose <= 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now - self.start_time;

        let period_id = (elapsed.as_millis() / PRINT_PERIOD.as_millis()) as i64;
        if period_id == self.last_printed_period {
            *self.stamps.back_mut().unwrap() = (now, written_bytes);
        } else {
            self.last_printed_period = period_id;
            self.stamps.push_back((now, written_bytes));
            if self.stamps.len() > KEEP_STAMPS_COUNT {
                self.stamps.pop_front();
            }

            self.print_progress_line(false);
        }
    }

    fn print_progress_line(&mut self, is_final: bool) {
        // Calculate the average over the last KEEP_STAMPS_COUNT periods.
        let mut speed = None;
        let (end_period_time, end_period_progress) = *self.stamps.back().unwrap();
        let (start_period_time, start_period_progress) = *self.stamps.front().unwrap();
        let delta_time = (end_period_time - start_period_time).as_millis() as usize;
        let delta_progress = end_period_progress - start_period_progress;
        if delta_time > 1000 {
            speed = Some(delta_progress * 1000 / delta_time);
        }

        // Adjust end_period_progress to be < filesize and equal to it on final call.
        let written_bytes = if let Some(filesize) = self.filesize {
            if end_period_progress > filesize || is_final {
                filesize
            } else {
                end_period_progress
            }
        } else {
            end_period_progress
        };

        // Calculate the ETA
        let mut eta = None;
        if let Some(speed) = speed {
            if let Some(filesize) = self.filesize {
                let remaining = filesize - written_bytes;
                let eta_secs = (remaining + speed - 1) / speed; // round up
                eta = Some(Duration::from_secs(eta_secs as u64));
            }
        }

        // Write the progress line
        write!(
            self.output,
            "{}{}\r",
            termion::clear::CurrentLine,
            Self::format_progress_line(written_bytes, self.filesize, speed, eta),
        )
        .ok();
        self.printed_at_least_once = true;
    }

    fn format_progress_line(
        written_bytes: usize,
        filesize: Option<usize>,
        speed: Option<usize>,
        eta: Option<Duration>,
    ) -> String {
        let percent = if let Some(filesize) = filesize {
            let filesize = std::cmp::max(filesize, 1);
            let ratio = (written_bytes as f64) / (filesize as f64);
            format!("{:.1}", f64::min(ratio, 1.0) * 100.0)
        } else {
            "---".into()
        };

        format!(
            "   {:>5} % {:>14} {:>16}   {}",
            percent,
            util::human_file_size(written_bytes),
            speed
                .map(|s| format!("{}/s", util::human_file_size(s)))
                .unwrap_or_default(),
            eta.map(|d| format!("ETA  {:}s", util::human_duration(d)))
                .unwrap_or_default(),
        )
    }
}

impl<'a> Drop for ProgressPrinter<'a> {
    fn drop(&mut self) {
        if self.printed_at_least_once {
            self.print_progress_line(true);
            write!(self.output, "\n\n").ok();
        }
    }
}