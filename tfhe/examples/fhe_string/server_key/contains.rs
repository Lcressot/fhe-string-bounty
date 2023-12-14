//! ServerKey implementation of str::contains related functions forciphertext::FheString objects

use tfhe::integer::ciphertext::RadixCiphertext;
use tfhe::integer::BooleanBlock;
use rayon::prelude::*;

use crate::ciphertext::{FheString, FheAsciiChar};
use crate::NUMBER_OF_BLOCKS;

use super::ServerKey;

impl ServerKey{

    /// Checks if a fhe_string trivially contains or not a pattern at some indices
    fn contains_trivially_indices(&self, fhe_string: &FheString, pattern: &FheString, indices_2:(usize,usize), index: usize) -> Option<RadixCiphertext>{
        let (start_2, end_2) = indices_2;

        // if the second string is empty, it is always contained
        if end_2-start_2 == 0 {
            return Some(self.make_trivial_bool(true));
        }
        // if the second string is not padded and goes above the length of the first one, the first one does not contain the second
        if !pattern.is_padded() & (end_2-start_2 + index > fhe_string.len()) {
            return Some(self.make_trivial_bool(false));
        }
        // if the first string is empty with no padding, it contains the second one only if it is empty
        if (fhe_string.len()==0) & (!fhe_string.is_padded()) {
            return Some(self.is_empty_indices(pattern, indices_2));
        }
        None
    }

    /// Checks if a fhe_string trivially contains or not a pattern
    fn contains_trivially(&self, fhe_string: &FheString, pattern: &FheString, index: usize) -> Option<RadixCiphertext>{
        self.contains_trivially_indices(fhe_string, pattern, (0, pattern.len()), index)
    }    

    /// Checks if a fhe_string contains a non padded pattern at a given index
    /// Example: "abcd" contains "bc" at index 1
    /// Warning: this function must be called on non padded pattern only
    fn contains_at_index_no_padding(&self, fhe_string: &FheString, pattern: &FheString, index: usize) -> RadixCiphertext {
        assert!( !pattern.is_padded(),
            "Should not call contains_at_index_no_padding with a pattern that may have padding"
        );
        assert!( index < fhe_string.len(), "index is above fhe_string length");

        // first of all check if the result is trivial:
        match self.contains_trivially(fhe_string, pattern, index){
            Some(encrypted_boolean) => {return encrypted_boolean;}
            None => {}
        }

        let len_2 = pattern.len();
     
        // or, we check that matching values are identical:
        
        // if the two strings are unencrypted
        if !fhe_string.is_encrypted() && !pattern.is_encrypted() {
            return self.eq_same_size_indices(fhe_string, (index, index+len_2), pattern, (0,len_2));
        }

        // if the first is clear and the other is encrypted
        if !fhe_string.is_encrypted() && pattern.is_encrypted() {
            let slice_1 = &fhe_string.chars()[index..index+len_2];
            let slice_2 = &pattern.fhe_chars()[0..len_2];
            return self.eq_same_size_fhe_chars_chars( slice_2, slice_1);
        }

        // if the first is encrypted
        let slice_1 = &fhe_string.fhe_chars()[index..index+len_2];

        // .. and the other is clear
        if fhe_string.is_encrypted() && !pattern.is_encrypted() {
            let slice_2_clear = &pattern.chars()[0..len_2];
            return self.eq_same_size_fhe_chars_chars(slice_1, slice_2_clear);
        }

        // else, both are encrypted

        // get a slice without the ending null character
        let slice_2 = &pattern.fhe_chars()[0..len_2];
        self.eq_same_size_fhe_chars( slice_1, slice_2)
    }


    /// Checks if a fhe_string_1 contains some slice of another pattern (padded or not), at a given index
    /// Example: "abcd" contains "bc\0\0" at index 1
    /// Note: when ones knows for sure the pattern is not padded, they should use contains_at_index_no_padding instead
    fn contains_at_index(&self, fhe_string: &FheString, pattern: &FheString, indices_2:(usize,usize), index: usize) -> RadixCiphertext {
        assert!( pattern.is_padded(),
            "Should not call contains_at_index with a pattern that has no padding"
        );
        let (start_2, end_2) = indices_2;
        assert!( index < fhe_string.len(), "index is above fhe_string length");

        // first of all check if the result is trivial:
        match self.contains_trivially_indices(fhe_string, pattern, indices_2, index){
            Some(encrypted_boolean) => {return encrypted_boolean;}
            None => {}
        }

        // then check wether the pattern goes beyond the length of the fhe_string
        // in this case, we check if the first cut slice is contained and the second cut slice is empty
        let len_2 = end_2-start_2;
        if len_2 + index > fhe_string.len(){
            // compute the extra length
            let extra_length = len_2 + index - fhe_string.len();
            // compute wether the second string without extra length is contained
            let is_contained_no_extra = self.contains_at_index(
                fhe_string,
                pattern,
                (0, len_2 - extra_length),
                index
            );
            // compute wether the second string is empty on its extra length
            let is_empty_extra = self.is_empty_indices( pattern, (len_2 - extra_length, len_2-1));
            return self.key.bitand_parallelized(&is_contained_no_extra, &is_empty_extra);
        }

        // at this point we know the second string does not go beyond the length of the first one
        // we check that for each matching values, they are either identical or the second one is null (if it is a padding character)
        // Note :null characters can only appear at the end of the fhe_strin_2, never in the middle
        
        // if the two strings are unencrypted
        if !fhe_string.is_encrypted() && !pattern.is_encrypted() {
            return self.eq_same_size_indices(fhe_string, (index, index+len_2), pattern, (0,len_2));
        }

        // if the first is clear and the other is encrypted
        if !fhe_string.is_encrypted() && pattern.is_encrypted() {
            let slice_1 = &fhe_string.chars()[index..index+len_2];
            let slice_2 = &pattern.fhe_chars()[start_2..end_2];
            
            // compute wether characters are equal or the second is null (padding character)         
            let equal_or_2nd_is_null = self.parallelized_vec_2_bool_function(
                slice_1,
                slice_2,
                |(c, fhe_c): (&char, &FheAsciiChar)|{
                    let (is_equal, second_is_null) = rayon::join(
                        || self.key.scalar_eq_parallelized(fhe_c.unwrap(), (*c) as u8).into_radix(1, &self.key),
                        || self.key.scalar_eq_parallelized(fhe_c.unwrap(), 0u8).into_radix(1, &self.key)
                    );
                    self.key.bitor_parallelized(&is_equal, &second_is_null)
                });

            // check if equal_or_2nd_is_null is true everywhere
            return self.all(equal_or_2nd_is_null);
        }

        // else, both are encrypted

        // get a slice 
        let slice_1 = &fhe_string.fhe_chars()[index..index+len_2];
        let slice_2 = &pattern.fhe_chars()[start_2..end_2];

        // compute wether characters are equal or the second is null (padding character)         
        let equal_or_2nd_is_null = self.parallelized_vec_2_bool_function(
            slice_1,
            slice_2,
            |(fhe_c_1, fhe_c_2): (&FheAsciiChar, &FheAsciiChar)|{
                let (is_equal, second_is_null) = rayon::join(
                    || self.key.eq_parallelized(fhe_c_1.unwrap(), fhe_c_2.unwrap()).into_radix(1, &self.key),
                    || self.key.scalar_eq_parallelized(fhe_c_2.unwrap(), 0u8).into_radix(1, &self.key)
                );
                self.key.bitor_parallelized(&is_equal, &second_is_null)
            });

        // check if equal_or_2nd_is_null is true everywhere
        self.all(equal_or_2nd_is_null)
    }    

    /// Compute a Vec<RadixCiphertext> containing wether fhe_string contains pattern at given index 
    /// Note: This function uses nested parallel computing for faster results
    pub fn contains_at_index_vec(&self, fhe_string: &FheString, pattern: &FheString) -> Vec<RadixCiphertext>{
        // Let's iterate over the range of indices the second string might be contained (in parallel)
        // Note: We use a nested parallel iteration here, because the function contains_at_index_no_padding
        //  is already a parallel version. This works well with rayon and is faster          
        if !pattern.is_padded(){
            // if the second string has no padding, the computation is easier because we don't care about padding
            return (0..=fhe_string.len()-pattern.len()).into_par_iter().map(
                    |index| self.contains_at_index_no_padding(fhe_string, pattern, index)
                    ).collect();
        }else{
            return (0..=fhe_string.len()-1).into_par_iter().map(
                    |index| self.contains_at_index(fhe_string, pattern, (0, pattern.len()), index)
                ).collect();
        }
    }

    /// Compute if a fhe_string contains a given pattern
    /// Warning: Requires reusable FheStrings
    pub fn contains(&self, fhe_string: &FheString, pattern: &FheString) -> RadixCiphertext {
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"contains");
        ServerKey::assert_is_reusable(pattern, &"contains");

        // first of all check if the result is trivial
        match self.contains_trivially(fhe_string, pattern, 0){
            Some(encrypted_boolean) => {return encrypted_boolean;}
            None => {}
        }

        let contains_at_index_vec = self.contains_at_index_vec(fhe_string, pattern);
        self.any(contains_at_index_vec)
    }

    /// Compute if a fhe_string starts with a given pattern
    /// Warning: Requires reusable FheStrings    
    pub fn starts_with(&self, fhe_string: &FheString, pattern: &FheString) -> RadixCiphertext {
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"starts_with");
        ServerKey::assert_is_reusable(pattern, &"starts_with");

        // first of all check if the result is trivial
        match self.contains_trivially(fhe_string, pattern, 0){
            Some(encrypted_boolean) => {return encrypted_boolean;}
            None => {}
        }

        // Starting with a string (with no padding) means containing it at index 0
        if !pattern.is_padded(){           
            // if the querry string has no padding, the computation is easier because we don't care about padding
            return self.contains_at_index_no_padding(fhe_string, pattern, 0);
        }else{
            return self.contains_at_index(fhe_string, pattern, (0, pattern.len()), 0);
        }
        
    }

    /// Compute if a fhe_string ends with a given pattern
    /// Warning: Requires reusable FheStrings    
    pub fn ends_with(&self, fhe_string: &FheString, pattern: &FheString) -> RadixCiphertext {
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"ends_with");
        ServerKey::assert_is_reusable(pattern, &"ends_with");

        // first of all check if the result is trivial
        match self.contains_trivially(fhe_string, pattern, 0){
            Some(encrypted_boolean) => {return encrypted_boolean;}
            None => {}
        }

        if !fhe_string.is_padded() & !pattern.is_padded(){           
            // if both fhe_strings have no padding, the result is easy
            return self.contains_at_index_no_padding(fhe_string, pattern, fhe_string.len()-pattern.len());
        }
        else if fhe_string.is_padded() & !pattern.is_padded(){
            // if the first fhe_string may have padding but the second does not

            // first we need to know the hidden length of both fhe_strings
            let hidden_len_1 = self.len(fhe_string);
            let len_2 = pattern.len();

            // We then check if there exists an index such that fhe_string contains pattern at this index
            // and the following part of fhe_string is only null padding characters, i.e index + len_2 >= hidden_len_1
            let contains_at_index_and_rest_null: Vec<RadixCiphertext> = 
                (0..=fhe_string.len()-1).into_par_iter().map(
                    |index| {
                        // wether contains at index:
                        let contains_at_index = self.contains_at_index_no_padding(fhe_string, pattern, index);
                        // wether the rest is null, i.e hidden_len_1 <= index + len_2 :
                        let rest_null = self.key.scalar_le_parallelized(&hidden_len_1, (len_2 + index) as u64).into_radix(1, &self.key);
                        // return AND value
                        self.key.bitand_parallelized(&contains_at_index, &rest_null)
                }).collect();
            // return if any
            self.any(contains_at_index_and_rest_null)
        }else{
            // if the two may have padding, the computation is heavier

            // first we need to know the hidden length of both fhe_strings:
            let hidden_len_1 = self.len(fhe_string);
            let hidden_len_2 = self.len(pattern);

            let n_blocks = ServerKey::compute_blocks_for_len(fhe_string.len() as u64);

            // We then check if there exists an index such that fhe_string contains pattern at this index
            // and the following part of fhe_string is only null padding characters, i.e index + hidden_len_2 >= hidden_len_1
            let contains_at_index_and_rest_null: Vec<RadixCiphertext> = 
                (0..=fhe_string.len()-1).into_par_iter().map(
                    |index| {
                        // wether contains at index:
                        let mut contains_at_index = self.contains_at_index(fhe_string, pattern, (0, pattern.len()), index);
                        self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut contains_at_index, n_blocks-1);

                        // wether the rest is null, i.e index + hidden_len_2 >= hidden_len_1:
                        let mut hidden_len_1_extended = hidden_len_1.clone();
                        let index_enc = self.key.create_trivial_radix(index as u64, n_blocks);
                        let mut addition = self.key.add_parallelized(&hidden_len_2, &index_enc);
                        // extend the two variables so they get the same block size
                        self.extend_equally(&mut addition, &mut hidden_len_1_extended);
                        let rest_null = self.key.ge_parallelized(&addition, &hidden_len_1_extended).into_radix(1, &self.key);

                        // return AND value
                        self.key.bitand_parallelized(&contains_at_index, &rest_null)
                }).collect();
            // return if any or if pattern is empty (in case it is padded empty)
            self.key.bitor_parallelized(
                &self.any(contains_at_index_and_rest_null),
                &self.is_empty(pattern)
            )
        }
        
    }   


    /// Returns the index where the pattern is found in fhe_string, and wether it has been found
    /// Warning: Requires reusable FheStrings       
    /// `reverse` wether to look from the right (rfind) or from the left (find)
    fn find_or_rfind(&self, fhe_string: &FheString, pattern: &FheString, reverse: bool) -> (RadixCiphertext, RadixCiphertext) {        

        // first of all check if the result is trivial
        match self.contains_trivially(fhe_string, pattern, 0){
            Some(encrypted_boolean) => {
                if reverse{
                    return (self.len(fhe_string), encrypted_boolean);
                }else{
                    return (self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS), encrypted_boolean);
                }
            }
            None => {}
        }

        // sequential is_all_zeros(i), parallel is_all_zeros & contains, parallel mul i + sum accumulation 

        // let us first get a vector telling for each index wether pattern is contained at this index:
        let contains_at_index_vec = self.contains_at_index_vec(fhe_string, pattern);
        let len = contains_at_index_vec.len();

        // then we want to compute the first index where the value is true, and record if any

        let n_blocks = ServerKey::compute_blocks_for_len(len as u64);

        // first, let's compute a vector is_all_zeros telling for each index
        // wether there was only zeros before the index in contains_at_index_vec
        let mut is_all_zeros = Vec::<RadixCiphertext>::with_capacity(len);
        // if reverse, reverse the index order
        let match_index = |index| if reverse{ len-1-index } else { index };
        // init with a true
        is_all_zeros.push(self.make_trivial_bool(true));
        // fill it sequentially (cannot use parallelization)
        (0..len).into_iter().for_each(
            |index|{
                let val = self.key.smart_bitand(
                    &mut is_all_zeros[index],
                    &mut self.not(&contains_at_index_vec[match_index(index)])
                );
                is_all_zeros.push(val);
        });

        // now compute the index where is_all_zeros AND contains_at_index_vec is true

        // first fill a vector with index * boolean to be summed
        let to_add_vec : Vec::<RadixCiphertext> = (0..len).into_par_iter().map(
            |index| {
                let mut is_all_zeros_and_contains_at_index = self.key.bitand_parallelized(&is_all_zeros[match_index(index)], &contains_at_index_vec[index]);
                let index_enc = self.key.create_trivial_radix(index as u64, n_blocks);
                self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut is_all_zeros_and_contains_at_index, n_blocks-1);
                self.key.mul_parallelized(&index_enc, &is_all_zeros_and_contains_at_index)
        }).collect();

        // sum the boolean * index to get the index
        let mut index = to_add_vec.into_par_iter().reduce(
            || self.key.create_trivial_zero_radix(n_blocks),
            |acc: RadixCiphertext, ele: RadixCiphertext| {
                self.key.add_parallelized(&acc, &ele)
            });

        // the last value of is_all_zeros tells us wether we found an index or not
        let mut index_found = self.not(&is_all_zeros[is_all_zeros.len()-1]);

        // Correct for the special case where rfind an encrypted empty string with padding, such as "\0\0"
        if reverse & pattern.is_padded(){
            let is_empty = self.is_empty(pattern);
            index = self.key.if_then_else_parallelized(
            	&BooleanBlock::convert::<RadixCiphertext>(&is_empty, &self.key),
            	&self.len(fhe_string),
            	&index);
            index_found = self.key.bitor_parallelized(&is_empty, &index_found);
        }

        (index, index_found)
    }   

    /// Returns the first index from the left where the pattern is found in fhe_string, and wether it has been found
    /// `reverse` wether to look from the right    
    pub fn find(&self, fhe_string: &FheString, pattern: &FheString) -> (RadixCiphertext, RadixCiphertext) {
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"find");
        ServerKey::assert_is_reusable(pattern, &"find");

        self.find_or_rfind(fhe_string, pattern, false)
    } 

    /// Returns the first index from the right where the pattern is found in fhe_string, and wether it has been found
    /// Warning: Requires reusable FheStrings       
    /// `reverse` wether to look from the right    
    pub fn rfind(&self, fhe_string: &FheString, pattern: &FheString) -> (RadixCiphertext, RadixCiphertext) {
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"rfind");
        ServerKey::assert_is_reusable(pattern, &"rfind");

        self.find_or_rfind(fhe_string, pattern, true)
    }                

}