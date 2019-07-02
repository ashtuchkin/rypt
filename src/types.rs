use failure::Fallible;

#[derive(Debug)]
pub struct Chunk {
    pub buffer: Vec<u8>, // NOTE: Actual data in this chunk is buffer[offset..]. Offset is introduced to help with alignment.
    pub offset: usize,
    pub is_last_chunk: bool,
    pub authentication_data: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ChunkConfig {
    pub input_chunk_offset: usize, // Input chunk offset requested
    pub input_chunk_asize: usize,  // Additional size to reserve for input chunks
    pub output_chunk_asize: usize, // Additional size to reserve for output chunks (wrt input offset)
}

pub trait StreamConverter: Send {
    fn get_chunk_config(&self) -> ChunkConfig;
    fn convert_chunk(&mut self, chunk: Chunk) -> Fallible<Chunk>;
}

#[derive(Debug)]
pub struct StreamCodecConfig {
    pub key_size: usize,
}

pub trait StreamCodec {
    fn get_config(&self) -> StreamCodecConfig;
    fn start_encoding(&self, key: &[u8]) -> Fallible<(Vec<u8>, Box<StreamConverter>)>;
    fn start_decoding(&self, key: &[u8], header: &[u8]) -> Fallible<Box<StreamConverter>>;
}

pub trait KeyDerivationFunction {
    fn derive_key_from_password(&self, password: &str, key_len: usize) -> Fallible<Vec<u8>>;
}
