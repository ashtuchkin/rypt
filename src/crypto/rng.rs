use crate::crypto::CryptoSystem;
use rand::{CryptoRng, RngCore};

/// Implements `rand` crate-compatible random generator from a CryptoSystem. It needs to be a
/// separate struct to avoid requiring that CryptoSystem be mutable (all RngCore require &mut self).   
pub struct CryptoSystemRng<'a> {
    cryptosys: &'a dyn CryptoSystem,
}

impl CryptoSystemRng<'_> {
    pub fn new(cryptosys: &dyn CryptoSystem) -> CryptoSystemRng {
        CryptoSystemRng { cryptosys }
    }
}

impl RngCore for CryptoSystemRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; std::mem::size_of::<u32>()];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; std::mem::size_of::<u64>()];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.cryptosys.fill_random_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CryptoSystemRng<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::instantiate_crypto_system;
    use failure::Fallible;
    use rand::prelude::*;

    #[test]
    fn test_basic() -> Fallible<()> {
        let cryptosys = instantiate_crypto_system(Default::default())?;

        let mut crypto_rng = CryptoSystemRng::new(&*cryptosys);

        let mut bytes = [0u8; 16];
        crypto_rng.fill(&mut bytes);
        assert_ne!(&bytes, &[0u8; 16]);

        // Use Rng interface
        assert!(crypto_rng.gen_bool(1.0));

        Ok(())
    }
}
