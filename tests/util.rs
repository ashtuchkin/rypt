use rand::distributions::Distribution;
use rand::Rng;
use std::ffi::{OsStr, OsString};
use std::io;
use std::io::Read;

pub struct ReadReceiver {
    receiver: crossbeam_channel::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    cursor: usize,
}

impl ReadReceiver {
    pub fn new(receiver: crossbeam_channel::Receiver<Vec<u8>>) -> ReadReceiver {
        ReadReceiver {
            receiver,
            buf: vec![],
            cursor: 0,
        }
    }

    pub fn read_all(&mut self) -> Result<String, io::Error> {
        let mut str = String::new();
        self.read_to_string(&mut str)?;
        return Ok(str);
    }
}

impl io::Read for ReadReceiver {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if self.cursor == self.buf.len() {
            match self.receiver.recv() {
                Ok(val) => {
                    self.buf = val;
                    self.cursor = 0;
                }
                Err(_) => {
                    // Disconnected
                    return Ok(0); // Eof
                }
            }
        }
        let len = std::cmp::min(buf.len(), self.buf.len() - self.cursor);
        buf[..len].copy_from_slice(&self.buf[self.cursor..self.cursor + len]);
        self.cursor += len;
        Ok(len)
    }
}

pub struct WriteSender {
    sender: crossbeam_channel::Sender<Vec<u8>>,
}

impl WriteSender {
    pub fn new(sender: crossbeam_channel::Sender<Vec<u8>>) -> WriteSender {
        WriteSender { sender }
    }
}

impl io::Write for WriteSender {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.sender
            .send(buf.to_owned())
            .map_err(|_| io::ErrorKind::NotConnected)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

pub fn create_read_write_pipe() -> (ReadReceiver, WriteSender) {
    let (sender, receiver) = crossbeam_channel::unbounded();
    (ReadReceiver::new(receiver), WriteSender::new(sender))
}

pub fn to_os_strs<T>(cmdline: &[T]) -> Vec<OsString>
where
    T: AsRef<OsStr>,
{
    cmdline.iter().map(|s| s.as_ref().into()).collect()
}

pub fn random_str(mut rng: &mut rand::RngCore, len: usize) -> String {
    rand::distributions::Alphanumeric
        .sample_iter(&mut rng)
        .take(len)
        .collect()
}

pub fn random_bytes(rng: &mut rand::RngCore, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill(bytes.as_mut_slice());
    bytes
}
