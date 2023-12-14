//! ServerKey implementation of repeat function for ciphertext::FheString objects

use crate::ciphertext::{FheString};
use super::ServerKey;

impl ServerKey {

    /// Repeat implementation for FheStrings
    ///
    /// Warning: if there is padding, the result will not be reusable,
    /// as it will contain empty characters in the string.
    /// Refer to ServerKey::repeat_reusable for getting reusable repeated FheStrings.
    ///
    /// Note: This function does not require that the FheString is reusable
	pub fn repeat(&self, fhe_string: &FheString, n: usize) -> FheString {
		fhe_string.repeat(n)
	}

    /// Repeat implementation for FheStrings that produce a reusable FheString
    /// Note: This function does not require that the FheString is reusable
    pub fn repeat_reusable(&self, fhe_string: &FheString, n: usize) -> FheString {        

        // Repeat the string and make it reusable
        let repeated_string = self.repeat(&fhe_string, n);

        if !repeated_string.is_reusable(){
            self.make_reusable(&repeated_string)
        }else{
            repeated_string
        }          
    }    

}