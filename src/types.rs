use crossbeam_channel::{Receiver, Sender};
use failure::Fallible;

#[derive(Debug)]
pub struct Chunk {
    pub buffer: Vec<u8>, // NOTE: Actual data in this chunk is buffer[offset..]. Offset is introduced to allow adding prefixes.
    pub offset: usize,
    pub is_last_chunk: bool,
}

#[derive(Debug)]
pub struct ChunkConfig {
    pub input_chunk_offset: usize, // Input chunk offset requested
    pub input_chunk_asize: usize,  // Additional size for input chunks
    pub output_chunk_asize: usize, // Additional size for output chunks (wrt input offset)
}

pub trait StreamConverter: Send {
    fn get_chunk_config(&self) -> ChunkConfig;
    fn convert_blocking(&mut self, input: Receiver<Chunk>, output: Sender<Chunk>) -> Fallible<()>;
}

#[derive(Debug)]
pub struct StreamCodecConfig {
    pub header_size: usize,
    pub key_size: usize,
}

pub trait StreamCodec {
    fn get_config(&self) -> StreamCodecConfig;
    fn start_encoding(
        &self,
        key: Vec<u8>,
        authenticate_data: Option<Vec<u8>>,
    ) -> Fallible<(Vec<u8>, Box<StreamConverter>)>;
    fn start_decoding(
        &self,
        key: Vec<u8>,
        header: Vec<u8>,
        authenticate_data: Option<Vec<u8>>,
    ) -> Fallible<Box<StreamConverter>>;
}

pub trait KeyDerivationFunction {
    fn derive_key_from_password(&self, password: &str, key_len: usize) -> Fallible<Vec<u8>>;
}
