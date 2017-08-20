use rmp_serde::{decode, encode};
use rmp_serde::{Serializer, Deserializer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::Path;

quick_error! {
    /// Password database error.
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) {
            from()
            cause(err)
        }
        Serialization(err: encode::Error) {
            from()
            cause(err)
        }
        Deserialization(err: decode::Error) {
            from()
            cause(err)
        }
    }
}

/// A helper trait to manage password database.
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct PassDb {
    users_and_hashes: BTreeMap<String, Vec<u8>>,
}

impl PassDb {
    /// Loads database from a given path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let input = File::open(path)?;
        let mut deserializer = Deserializer::new(&input);
        Ok(Deserialize::deserialize(&mut deserializer)?)
    }

    /// Saves the database.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut output = File::create(path)?;
        self.serialize(&mut Serializer::new(&mut output))?;
        Ok(())
    }

    /// Creates an empty database.
    pub fn new() -> Self {
        Self { users_and_hashes: Default::default() }
    }

    /// Finds a password hash for a given user.
    pub fn find_hash(&self, user_id: &str) -> Option<Vec<u8>> {
        self.users_and_hashes.get(user_id).cloned()
    }

    /// Adds a password hash to the database.
    pub fn insert(&mut self, user_id: &str, hash: Vec<u8>) {
        self.users_and_hashes.insert(user_id.into(), hash);
    }

    /// Removes a user from the database.
    pub fn remove(&mut self, user_id: &str) {
        self.users_and_hashes.remove(user_id);
    }

    /// List users in the database.
    pub fn list_users(&self) -> Vec<String> {
        self.users_and_hashes.keys().cloned().collect()
    }
}
