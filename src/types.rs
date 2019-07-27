use failure::Fallible;

#[derive(Debug)]
pub struct Chunk {
    pub buffer: Vec<u8>,
    pub is_last_chunk: bool,
    pub chunk_idx: u64, // Chunk consecutive number, starting from 0.
}

#[derive(Debug)]
pub struct ChunkConfig {
    pub input_chunk_asize: usize, // Additional size to reserve for input chunks
    pub output_chunk_asize: usize, // Additional size to reserve for output chunks (wrt input offset)
}

pub trait StreamConverter: Send {
    fn get_chunk_config(&self) -> ChunkConfig;
    fn convert_chunk(&mut self, chunk: Chunk) -> Fallible<Chunk>;
}
