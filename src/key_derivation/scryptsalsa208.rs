use std::os::raw::c_void;
use std::convert::TryInto;

use failure::{Error};
use libsodium_sys::{
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,  // u64
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE,  // usize
    randombytes_buf,
};
use crate::errors::MyError;
use crate::header::SCryptSalsa208SHA256Config;
use crate::types::KeyDerivationFunction;

const SCRYPTSALSA208SHA256_SALTBYTES: usize = libsodium_sys::crypto_pwhash_scryptsalsa208sha256_SALTBYTES as usize;


pub struct SCryptSalsa208SHA256 {
    opslimit: u64,
    memlimit: u64,
    salt: [u8; SCRYPTSALSA208SHA256_SALTBYTES],
}

impl SCryptSalsa208SHA256 {
    pub fn new(config: &SCryptSalsa208SHA256Config) -> Result<Self, Error> {
        Ok(SCryptSalsa208SHA256 {
            opslimit: config.opslimit,
            memlimit: config.memlimit,
            salt: config.salt.as_slice().try_into()  // Check the length is SCRYPTSALSA208SHA256_SALTBYTES
                .map_err(|_| MyError::InvalidHeader("Invalid salt length for SCryptSalsa208SHA256".into()))?,
        })
    }

    pub fn default_config_random_seed() -> SCryptSalsa208SHA256Config {
        let mut salt = vec![0u8; SCRYPTSALSA208SHA256_SALTBYTES];
        unsafe {randombytes_buf(salt.as_mut_ptr() as *mut c_void, salt.len())};

        SCryptSalsa208SHA256Config {
            salt,
            opslimit: crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE as u64,
            memlimit: crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE as u64,
        }
    }
}

impl KeyDerivationFunction for SCryptSalsa208SHA256 {
    fn derive_key_from_password(&self, password: &str, key_len: usize) -> Result<Vec<u8>, Error> {
        let mut out_key = vec![0u8; key_len];
        let rc = unsafe {
            libsodium_sys::crypto_pwhash_scryptsalsa208sha256(
                out_key.as_mut_ptr(),
                key_len as u64,
                password.as_ptr() as *const i8,
                password.len() as u64,
                self.salt.as_ptr(),
                self.opslimit as u64,
                self.memlimit as usize,
            )
        };
        if rc != 0 {
            return Err(MyError::KeyDerivationError.into());
        }

        Ok(out_key)
    }
}