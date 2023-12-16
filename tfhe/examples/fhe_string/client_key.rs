//! The client_key module implements a wrapper for a tfhe::integer::client_key::RadixClientKey object
//! It allows to create encrypted ciphertext::FheString objects

use tfhe::integer::client_key::RadixClientKey;
use serde::{Serialize, Deserialize};

use crate::ciphertext::FheString;
use tfhe::integer::ciphertext::RadixCiphertext;

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey{
    key: RadixClientKey,
}

impl ClientKey{

    pub fn new(key: RadixClientKey) -> Self {    
        Self {
            key,
        }
    }

    pub fn encrypt_string(&self, string: &String, padding: usize) -> FheString{
        FheString::from_string(string).encrypt(&self.key, padding) 
    }

    pub fn encrypt_str(&self, string: &str, padding: usize) -> FheString{
        self.encrypt_string(&string.to_string(), padding)
    }

    pub fn encrypt_fhe_string(&self, fhe_string: &FheString, padding: usize) -> FheString{
        assert!(fhe_string.is_clear(), "FheString should be clear");
        fhe_string.encrypt(&self.key, padding)
    }        

    pub fn decrypt_fhe_string(&self, fhe_string: &FheString) -> FheString{
        assert!(fhe_string.is_encrypted(), "FheString should be encrypted");
        fhe_string.decrypt(&self.key)
    }

    pub fn decrypt_to_string(&self, fhe_string: &FheString) -> String{
        assert!(fhe_string.is_encrypted(), "FheString should be encrypted");
        fhe_string.decrypt(&self.key).to_string()
    }    

    pub fn decrypt_bool(&self, fhe_boolean: &RadixCiphertext) -> bool {
        self.key.decrypt::<u8>(fhe_boolean) == 1
    }    
    
    pub fn encrypt_u8(&self, integer: &u8) -> RadixCiphertext{
        self.key.encrypt(*integer as u8)
    }    

    pub fn decrypt_u8(&self, integer: &RadixCiphertext) -> u8 {
        self.key.decrypt::<u8>(integer)
    }  

    pub fn decrypt_u64(&self, integer: &RadixCiphertext) -> u64 {
        self.key.decrypt::<u64>(integer)
    }         
}
