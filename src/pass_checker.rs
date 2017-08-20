use ring::{digest, pbkdf2};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::path::Path;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

/// A helper class to hash and check passwords in a more or less secure way.
/// Under the cover `pbkdf2` & `sha256` are used.
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct PassChecker {
    iterations: u32,
    salt: Vec<u8>,
}

impl PassChecker {
    /// Creates a new instance of the `PassChecker`.
    pub fn new(hash_iterations: u32, salt: Vec<u8>) -> Self {
        Self {
            iterations: hash_iterations,
            salt: salt,
        }
    }

    /// Loads configuration from a file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<Error>> {
        let input = File::open(path)?;
        let mut deserializer = Deserializer::new(&input);
        Ok(Deserialize::deserialize(&mut deserializer)?)
    }

    /// Saves configuration to a file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<Error>> {
        let mut output = File::create(path)?;
        self.serialize(&mut Serializer::new(&mut output))?;
        Ok(())
    }

    /// Checks a password.
    pub fn check_password(&self, user_id: &str, hash: &[u8], password: &str) -> bool {
        let salt = self.make_salt(user_id);
        pbkdf2::verify(
            &DIGEST_ALG,
            self.iterations,
            &salt,
            password.as_bytes(),
            hash,
        ).is_ok()
    }

    /// Calculates a hash for given credentials.
    pub fn hash_password(&self, user_id: &str, password: &str) -> Vec<u8> {
        let salt = self.make_salt(user_id);
        let mut result = vec![0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            DIGEST_ALG,
            self.iterations,
            &salt,
            password.as_bytes(),
            &mut result,
        );
        result
    }

    /// A helper function to make a 'salt' that can be used to 'salt' a password.
    fn make_salt(&self, user_id: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.salt.len() + user_id.as_bytes().len());
        salt.extend(&self.salt);
        salt.extend(user_id.as_bytes());
        salt
    }
}
