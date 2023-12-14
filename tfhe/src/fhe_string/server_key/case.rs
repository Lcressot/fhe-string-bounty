//! ServerKey implementation of casing functions to process FheString objects

use tfhe::integer::ciphertext::RadixCiphertext;
use rayon::prelude::*;

use crate::ciphertext::FheString;
use crate::ciphertext::FheAsciiChar;
use crate::NUMBER_OF_BLOCKS;

use super::ServerKey;

impl ServerKey{

    pub fn to_lowercase(&self, fhe_string: &FheString) -> FheString{

        // if the fhe_string is empty, just clone it
        if fhe_string.len()==0 {
            return fhe_string.clone();
        }

    	// if fhe_string is clear
    	if !fhe_string.is_encrypted(){
    		return FheString::from_string( &fhe_string.to_string().to_lowercase() );
    	}

    	// else, fhe_string is encrypted

        // compute wether characters are >=65 where 65 is 'A'
        // and wether they are <=90 where 90 is 'Z'
        let (is_ge_65, is_le_90) = rayon::join(
        || self.apply_parallelized_vec(
            fhe_string.fhe_chars(),
            |c| self.key.scalar_ge_parallelized(c.unwrap(), 65u8)
        ),
        || self.apply_parallelized_vec(
            fhe_string.fhe_chars(),
            |c| self.key.scalar_le_parallelized(c.unwrap(), 90u8)
        ));

        // trivially encrypt the number 32 :
        // Note: multiplying by the encrypted 32 instead of the scalar 32u8 is faster here, I don't know why
        let ct_32u8 = self.key.create_trivial_radix(32u8, NUMBER_OF_BLOCKS);

        let fhe_chars = fhe_string.fhe_chars();
        let lower_case_values: Vec<RadixCiphertext> = (0..fhe_string.len()).into_par_iter().map(
            |index| {
                let mut is_uppercase = self.key.bitand_parallelized(&is_ge_65[index], &is_le_90[index]);
                // here we need is_uppercase to be 4 blocks so it can be multiplied with a 32u8
                self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut is_uppercase, NUMBER_OF_BLOCKS-1);
                let mut res = self.key.mul_parallelized(&ct_32u8, &is_uppercase);
                // TODO: I cannot tell why but scalar_mul is slower:
                // let mut res = self.key.small_scalar_mul_parallelized(&mut is_uppercase, 32u8);
                self.key.add_assign_parallelized(&mut res, fhe_chars[index].unwrap());
                res
            }).collect();

        FheString::from_encrypted(lower_case_values, fhe_string.is_padded(), fhe_string.is_reusable())
    } 

    pub fn to_uppercase(&self, fhe_string: &FheString) -> FheString{

        // if the fhe_string is empty, just clone it
        if fhe_string.len()==0 {
            return fhe_string.clone();
        }
        
   		// if fhe_string is clear
    	if !fhe_string.is_encrypted(){
    		return FheString::from_string( &fhe_string.to_string().to_uppercase() );
    	}

    	// else, fhe_string is encrypted	

        // compute wether characters are >=97 where 97 is 'a'
        // and wether they are <=122 where 122 is 'z'
        let (is_ge_97, is_le_122) = rayon::join(
        || self.apply_parallelized_vec(
            fhe_string.fhe_chars(),
            |c| self.key.scalar_ge_parallelized(c.unwrap(), 97u8)
        ),
        || self.apply_parallelized_vec(
            fhe_string.fhe_chars(),
            |c| self.key.scalar_le_parallelized(c.unwrap(), 122u8)
        ));

        // trivially encrypt the number 32 :
        // Note: multiplying by the encrypted 32 instead of the scalar 32u8 is faster here, I don't know why
        let ct_32u8 = self.key.create_trivial_radix(32u8, NUMBER_OF_BLOCKS);

        let fhe_chars = fhe_string.fhe_chars();
        let upper_case_values: Vec<RadixCiphertext> = (0..fhe_string.len()).into_par_iter().map(
            |index| {                
                let mut is_lowercase = self.key.bitand_parallelized(&is_ge_97[index], &is_le_122[index]);
                // here we need is_lowercase to be 4 blocks so it can be multiplied with a 32u8
                self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut is_lowercase, NUMBER_OF_BLOCKS-1);
                let mut res = self.key.mul_parallelized(&ct_32u8, &is_lowercase);
                // TODO: I cannot tell why but scalar_mul is slower:
                // let mut res = self.key.small_scalar_mul_parallelized(&mut is_lowercase, 32u8);
                res = self.key.sub_parallelized(fhe_chars[index].unwrap(), &res);
                res
            }).collect();

        FheString::from_encrypted(upper_case_values, fhe_string.is_padded(), fhe_string.is_reusable())
    }

    /// Compute wether a FheString is equal to another FheString while ignoring case
    /// Warning: Requires reusable FheStrings    
    pub fn eq_ignore_case(&self, fhe_string_1: &FheString, fhe_string_2: &FheString) -> RadixCiphertext{
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_1, &"eq_ignore_case");
        ServerKey::assert_is_reusable(fhe_string_2, &"eq_ignore_case");

        self.eq( &self.to_lowercase(fhe_string_1), &self.to_lowercase(fhe_string_2) )
    }

}