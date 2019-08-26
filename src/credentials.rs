use crate::crypto::{AEADKey, PrivateKey, PublicKey};

// TODO: is it even a credential? Maybe rename?
#[derive(Debug, PartialEq, Clone)]
pub struct ComplexCredential {
    pub sub_creds: Vec<(usize, Credential)>,
    pub num_shares: usize,
    pub threshold: usize,
}

#[derive(Clone)] // Debug and PartialEq implemented below
pub enum Credential {
    Password(String),
    SymmetricKey(AEADKey),
    PublicKey(PublicKey),       // Only for encryption
    PrivateKey(PrivateKey),     // Only for decryption
    Complex(ComplexCredential), // Only for encryption
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Credential::Password(_) => write!(f, "Credential::Password"),
            Credential::SymmetricKey(_) => write!(f, "Credential::SymmetricKey"),
            Credential::PublicKey(_) => write!(f, "Credential::PublicKey"),
            Credential::PrivateKey(_) => write!(f, "Credential::PrivateKey"),
            Credential::Complex(c) => write!(f, "Credential::Complex({:?})", c),
        }
    }
}

impl std::cmp::PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (Credential::Password(pwd1), Credential::Password(pwd2)) => pwd1 == pwd2,
            (Credential::SymmetricKey(key1), Credential::SymmetricKey(key2)) => key1 == key2,
            (Credential::PublicKey(key1), Credential::PublicKey(key2)) => key1 == key2,
            (Credential::PrivateKey(key1), Credential::PrivateKey(key2)) => {
                key1.as_ref() == key2.as_ref()
            }
            (Credential::Complex(key1), Credential::Complex(key2)) => key1 == key2,
            _ => false,
        }
    }
}
