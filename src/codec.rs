use failure::{Fail, Error};
use crossbeam_channel::{Sender, Receiver};

#[derive(Fail, Debug)]
pub enum MyError {
    #[fail(display = "Sodium library initialization error")]
    InitError(()),

    #[fail(display = "Password required")]
    PasswordRequired,

    #[fail(display = "Decryption Error")]
    DecryptionError,

    #[fail(display = "Invalid header")]
    InvalidHeader,

    #[fail(display = "Thread Join Error")]
    ThreadJoinError,

    #[fail(display = "Unknown encoding algorithm: {}", _0)]
    UnknownAlgorithm(String),

    #[fail(display = "Encoding algorithm is unsupported by this CPU")]
    HardwareUnsupported,
}


#[derive(Debug)]
pub struct Chunk {
    pub buffer: Vec<u8>,  // NOTE: Actual data in this chunk is buffer[offset..]. Offset is introduced to allow adding prefixes.
    pub offset: usize,
    pub is_last_chunk: bool,
}

pub struct ChunkConfig {
    pub input_chunk_offset: usize,  // Input chunk offset requested
    pub input_chunk_asize: usize,   // Additional size for input chunks
    pub output_chunk_asize: usize,   // Additional size for output chunks (wrt input offset)
}

pub trait StreamConverter: Send {
    fn get_chunk_config(&self) -> ChunkConfig;
    fn convert_blocking(&mut self, input: Receiver<Chunk>, output: Sender<Chunk>) -> Result<(), Error>;
}

pub struct StreamCodecConfig {
    pub header_size: usize,
    pub key_size: usize,
}

pub trait StreamCodec {
    fn get_config(&self) -> StreamCodecConfig;
    fn start_encoding(&self, key: Vec<u8>) -> Result<(Vec<u8>, Box<StreamConverter>), Error>;
    fn start_decoding(&self, key: Vec<u8>, header: Vec<u8>) -> Result<Box<StreamConverter>, Error>;
}