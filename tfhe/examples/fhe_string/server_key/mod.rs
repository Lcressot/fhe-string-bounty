//! The server_key module implements a wrapper for a tfhe::integer::server_key::ServerKey object
//! It allows to process ciphertext::FheString objects

use tfhe::integer::server_key::ServerKey as IntegerServerKey;
use serde::{Serialize, Deserialize};

use tfhe::integer::ciphertext::{RadixCiphertext, IntegerCiphertext};
use tfhe::integer::BooleanBlock;
use rayon::prelude::*;
use std::cmp;

use crate::ciphertext::FheString;
use crate::ciphertext::FheAsciiChar;
use crate::NUMBER_OF_BLOCKS;

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey{
    key: IntegerServerKey,
}

impl ServerKey{

    pub fn new(key: IntegerServerKey) -> Self {    
        Self {
            key,
        }
    }

    /// Encrypt a clear FheString trivially
    pub fn trivial_encrypt_fhe_string(&self, fhe_string: &FheString, padding: usize) -> FheString{
        fhe_string.trivial_encrypt(&self.key, padding)
    }

    /// Encrypt a string trivially
    pub fn trivial_encrypt_string(&self, string: &String, padding: usize) -> FheString{
        self.trivial_encrypt_fhe_string(&FheString::from_string(string), padding)
    }

    /// Encrypt a str trivially
    pub fn trivial_encrypt_str(&self, string: &str, padding: usize) -> FheString{
        self.trivial_encrypt_fhe_string(&FheString::from_str(string), padding)
    }

    /// Create a trivial boolean RadixCiphertext from bool value
    fn make_trivial_bool(&self, boolean: bool) -> RadixCiphertext{
        if boolean{
            self.key.create_trivial_radix(1u8, 1)            
        }else{
            self.key.create_trivial_zero_radix(1)
        }
    }    

    /// Compute the boolean not value of a boolean RadixCipherText
    fn not(&self, boolean_value: &RadixCiphertext) -> RadixCiphertext{
        let mut not_value = self.make_trivial_bool(true);
        self.key.sub_assign_parallelized(&mut not_value, boolean_value);
        not_value
    }

    /// Compute in parallel wether all values of a Vec<RadixCiphertext> are true
    fn all(&self, values: Vec<RadixCiphertext>) -> RadixCiphertext{
        // check if all values are true with a rayon parallized bitand reduction
        let result = values.into_par_iter().reduce(
            || self.make_trivial_bool(true),
            |acc: RadixCiphertext, ele: RadixCiphertext| {
                self.key.bitand_parallelized(&acc, &ele)
        });
        result
    }

    /// Compute in parallel wether any value of a Vec<RadixCiphertext> is true
    fn any(&self, values: Vec<RadixCiphertext>) -> RadixCiphertext{
        // check if any values is true with a rayon parallized bitor reduction
        let result = values.into_par_iter().reduce(
            || self.make_trivial_bool(false),
            |acc: RadixCiphertext, ele: RadixCiphertext| {
                self.key.bitor_parallelized(&acc, &ele)
        });
        result
    }      

    /// Assert that a FheString is reusable
    /// `function_name` the name of the function where the assertion occurs, to keep track of it in debug
    fn assert_is_reusable(fhe_string: &FheString, function_name: &str){
        let alert_message = format!("The FheString is not reusable in function {}", function_name);
        assert!(fhe_string.is_reusable(), "{}", alert_message);
    }

    /// Compute the number of blocks required to encrypt a given number
    /// Return n such that 2^N is above the provided number
    fn compute_blocks_for_len(x: u64) -> usize {        
        let n = (x as f64).log2().ceil() as usize;
        n+1
    }

    /// Extend one of two RadixCiphertext variables if needed so that they get the same block size
    fn extend_equally(&self, var_1: &mut RadixCiphertext, var_2: &mut RadixCiphertext){
        let diff_blocks: isize = var_1.blocks().len() as isize - var_2.blocks().len() as isize;
        if diff_blocks < 0{
            self.key.extend_radix_with_trivial_zero_blocks_msb_assign(var_1, isize::abs(diff_blocks) as usize);
        }else if diff_blocks>0{
            self.key.extend_radix_with_trivial_zero_blocks_msb_assign(var_2, diff_blocks as usize);
        }else{}        
    }

    // /// Apply a parallelized boolean function to all values of a Vec<T> in parallel with rayon par_iter parallel iterator
    // /// Warning: The results are cast to 2-bits for faster boolean representation
    fn apply_parallelized_vec<F, T>(&self, vec: &[T], f: F) -> Vec<RadixCiphertext>
    where
        F: Fn(&T) -> RadixCiphertext + std::marker::Sync,
        T: Sync,
    {
        let result: Vec<RadixCiphertext> = vec.par_iter().map(
            |item|{
                let mut res = f(item);
                // trim to 2 bits to gain speed
                let trim_len = res.blocks().len()-1;
                self.key.trim_radix_blocks_msb_assign(&mut res, trim_len);
                res                
        }).collect();
        result
    }

    /// Apply a parallelized boolean function to all values of Vec<T> and Vec<Q> in parallel with rayon par_iter parallel iterator
    /// Warning: The results are cast to 2-bits for faster boolean representation
    fn parallelized_vec_2_bool_function<F, T, Q>(&self, vec_1: &[T], vec_2: &[Q], f: F) -> Vec<RadixCiphertext>
    where
        T: Sync,
        Q: Sync,
        F: Fn((&T, &Q)) -> RadixCiphertext + std::marker::Sync,
    {
        assert!(vec_1.len() == vec_2.len(), "vec_1 and vec_2 must have identical size");

        let result: Vec<RadixCiphertext> = (0..vec_1.len()).into_par_iter().map(
            |index|{
                let mut res = f((&vec_1[index], &vec_2[index]));
                let trim_len = res.blocks().len()-1;
                // trim to 2 bits to gain speed
                self.key.trim_radix_blocks_msb_assign(&mut res, trim_len);
                res
            }).collect();
        result   
    }  

    /// Compute a Vec::<RadixCiphertext> with values of an encrypted FheString set to zero
    /// where Vec::<RadixCiphertext> vec_where is true at given indices
    fn set_zero_where_indices(
        &self,
        fhe_string: &FheString,
        vec_where: &Vec::<RadixCiphertext>,
        start_index:usize,
        end_index:usize
    )-> Vec::<RadixCiphertext> {
        assert!(fhe_string.is_encrypted(), "FheString object should be encrypted");

        let zero: RadixCiphertext = self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);        
        (start_index..end_index).into_par_iter().map(
            |index|{
                if index >= vec_where.len(){
                    fhe_string.fhe_chars()[index].unwrap().clone()
                }else if index >= fhe_string.len(){
                    zero.clone()
                }else{
                    self.key.if_then_else_parallelized(
                        &BooleanBlock::convert::<RadixCiphertext>(&vec_where[index], &self.key),
                        &zero,
                        fhe_string.fhe_chars()[index].unwrap()
                    )
                }
        }).collect()
    }

    /// Compute a Vec::<RadixCiphertext> with values of an encrypted FheString set to zero
    /// where Vec::<RadixCiphertext> vec_where is true
    fn set_zero_where(&self, fhe_string: &FheString, vec_where: &Vec::<RadixCiphertext>) -> Vec::<RadixCiphertext>{
        self.set_zero_where_indices(fhe_string, vec_where, 0, fhe_string.len())
    }      

    /// Compute the hidden length of a FheString which is the number of non-zero characters
    pub fn len(&self, fhe_string: &FheString) -> RadixCiphertext{
        // return a trivial encrypted 0 if the visible length of the FheString is 0
        if fhe_string.len() == 0 {
            return self.make_trivial_bool(false);
        }

        let n_blocks = ServerKey::compute_blocks_for_len(fhe_string.len() as u64);

        // return a trivial encrypted length if the length of the FheString is not hidden
        if !fhe_string.is_padded() {
            return self.key.create_trivial_radix(fhe_string.len() as u64, n_blocks);
        }

        // return a trivial encrypted length if the fhe_string is clear
        if !fhe_string.is_encrypted() {
            return self.key.create_trivial_radix( fhe_string.to_string().len() as u64, n_blocks);
        }

        // the FheString is encrypted and has a non zero hidden length

        // compute which characters are non zero in parallel with rayon par_iter parallel iterator
        let greater_than_zero = self.apply_parallelized_vec(
            fhe_string.fhe_chars(),
            |c: &FheAsciiChar| self.key.scalar_ne_parallelized(c.unwrap(), 0u8).into_radix(1, &self.key)
            );        

        // sum up the number of ones in greater_than_zero
        let hidden_length = greater_than_zero.into_par_iter().reduce(
            || self.key.create_trivial_zero_radix(n_blocks),
            |acc: RadixCiphertext, ele: RadixCiphertext| {
                self.key.add_parallelized(&acc, &ele)
        });

        hidden_length.clone()        
    }

    /// Compute wether a part of FheString is empty, i.e. wether it is empty or composed only of \0
    fn is_empty_indices(&self, fhe_string: &FheString, indices: (usize, usize)) -> RadixCiphertext{
        let (start, end) = indices;

        // return a trivial encrypted 1 if the visible length of the FheString is 0
        if end-start == 0 {
            return self.key.create_trivial_radix(1u8, 1);
        }

        // if the fhe_string is clear
        if !fhe_string.is_encrypted() {
            return self.make_trivial_bool( fhe_string.slice_to_string(start, end) == "" );
        }

        // the FheString is encrypted and has a non zero hidden length

        // compute which characters are zero
        let equal_zero = self.apply_parallelized_vec(
            &fhe_string.fhe_chars()[start..end],
            |c: &FheAsciiChar| self.key.scalar_eq_parallelized(c.unwrap(), 0u8).into_radix(1, &self.key)
            );

        // return true if all are one
        self.all(equal_zero)
    } 

    /// Compute wether a FheString is empty, i.e. wether it is empty or composed only of \0
    pub fn is_empty(&self, fhe_string: &FheString) -> RadixCiphertext{
        self.is_empty_indices(fhe_string, (0, fhe_string.len()))
    } 

    /// Compute wether two [FheAsciiChar] are identical
    /// Note: working with slices avoids having to make sub-strings copies
    fn eq_same_size_fhe_chars(&self, fhe_chars_1: &[FheAsciiChar], fhe_chars_2: &[FheAsciiChar]) -> RadixCiphertext {
        assert!(fhe_chars_1.len() == fhe_chars_2.len(),
            "fhe_chars vecs must have identical length, here: {} and {}", fhe_chars_1.len(), fhe_chars_2.len());
        
        // compute equalities
        let equalities = self.parallelized_vec_2_bool_function(
            fhe_chars_1,
            fhe_chars_2,
            |(fhe_c_1, fhe_c_2): (&FheAsciiChar, &FheAsciiChar)|
                self.key.eq_parallelized(fhe_c_1.unwrap(), fhe_c_2.unwrap()).into_radix(1, &self.key)
            );

        // check if all equalities are true with a rayon parallized bitand reduction
        self.all(equalities)
    }


    /// Compute wether a [FheAsciiChar] is identical to a [char]
    /// Note: working with slices avoids having to make sub-strings copies
    fn eq_same_size_fhe_chars_chars(&self, fhe_chars: &[FheAsciiChar], chars: &[char]) -> RadixCiphertext {
        assert!(fhe_chars.len() == chars.len(),
            "fhe_chars and char vecs must have identical length, here: {} and {}", fhe_chars.len(), chars.len());
        
        // compute equalities
        let equalities = self.parallelized_vec_2_bool_function(
            fhe_chars,
            chars,
            |(fhe_c, c): (&FheAsciiChar, &char)|
                self.key.scalar_eq_parallelized(fhe_c.unwrap(), (*c) as u8).into_radix(1, &self.key)
            );

        // check if all equalities are true with a rayon parallized bitand reduction
        self.all(equalities)
    }    

    /// Compute wether a FheString is equal to another FheString of same size
    fn eq_same_size_indices(&self, fhe_string_1: &FheString, indices_1: (usize,usize),
                                   fhe_string_2: &FheString, indices_2: (usize,usize)) -> RadixCiphertext{
        let (start_1, end_1) = indices_1;
        let (start_2, end_2) = indices_2;

        assert!(end_1 - start_1 == end_2 - start_2,
            "fhe_strings must have identical visible length, here: {} and {}", end_1 - start_1, end_2 - start_2);

        // the two strings are empty
        if end_1 - start_1 == 0 {
            return self.make_trivial_bool(true);
        }

        // if the two strings are unencrypted
        if !fhe_string_1.is_encrypted() && !fhe_string_2.is_encrypted() {
            return self.make_trivial_bool( fhe_string_1.to_string()[start_1..end_1] == fhe_string_2.to_string()[start_2..end_2] );
        }

        // if the first is encrypted and the other is clear
        if fhe_string_1.is_encrypted() && !fhe_string_2.is_encrypted() {
            return self.eq_same_size_fhe_chars_chars( &fhe_string_1.fhe_chars()[start_1..end_1], &fhe_string_2.chars()[start_2..end_2]);
        }

        // if the first is clear and the other is encrypted
        if !fhe_string_1.is_encrypted() && fhe_string_2.is_encrypted() {
            return self.eq_same_size_indices(fhe_string_2, indices_2, fhe_string_1, indices_1);
        }

        // both fhe_strings are not empty and encrypted
        self.eq_same_size_fhe_chars(&fhe_string_1.fhe_chars()[start_1..end_1], &fhe_string_2.fhe_chars()[start_2..end_2])
    } 

    /// Compute wether a FheString is equal to another FheString of same size
    fn eq_same_size(&self, fhe_string_1: &FheString, fhe_string_2: &FheString) -> RadixCiphertext{
        self.eq_same_size_indices(fhe_string_1, (0,fhe_string_1.len()), fhe_string_2, (0,fhe_string_2.len()))
    } 


    /// Compute wether a FheString is equal to another FheString
    /// Warning: Requires reusable FheStrings
    pub fn eq(&self, fhe_string_1: &FheString, fhe_string_2: &FheString) -> RadixCiphertext{
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_1, &"eq");
        ServerKey::assert_is_reusable(fhe_string_2, &"eq");

        let len_1 = fhe_string_1.len();
        let len_2 = fhe_string_2.len();
        if len_1 == len_2 {
            self.eq_same_size(fhe_string_1, fhe_string_2)
        } else if len_1 > len_2 {
            if len_2 == 0{
                // this should not happen as FheString are supposed to have at least one \0, but substrings may be empty
                self.is_empty(fhe_string_1)
            }else{
                // when the first fhe_string is longer, the fhe_strings are equal if
                // they are equal for the length of the second fhe_string and the rest is empty (made of zeros)
                let (substr_equal, rest_empty) = rayon::join(
                    || self.eq_same_size_indices(fhe_string_1, (0,len_2), fhe_string_2, (0,len_2)),
                    || self.is_empty_indices(fhe_string_1, (len_2,len_1))
                );
                self.key.bitand_parallelized(&substr_equal, &rest_empty)
            }
        } else {
            if len_1 == 0{
                // this should not happen as FheString are supposed to have at least one \0, but substrings may be empty
                self.is_empty(fhe_string_2)
            }else{
                // same but opposite when the second fhe_string is longer
                let (substr_equal, rest_empty) = rayon::join(
                    || self.eq_same_size_indices(fhe_string_1, (0,len_1) , fhe_string_2, (0,len_1)),
                    || self.is_empty_indices(fhe_string_2, (len_1,len_2))
                );
                self.key.bitand_parallelized(&substr_equal, &rest_empty)
            }
        }
    }    

    /// Compute wether a FheString is not equal to another FheString
    /// Warning: Requires reusable FheStrings
    pub fn ne(&self, fhe_string_1: &FheString, fhe_string_2: &FheString) -> RadixCiphertext{
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_1, &"ne");
        ServerKey::assert_is_reusable(fhe_string_2, &"ne");

        let mut is_equal = self.eq(fhe_string_1, fhe_string_2);
        self.not(&mut is_equal)
    }


    /// Make an encrypted FheString reusable. All null characters (if any) that are present in the middle of the string
    /// are moved at the end of the sequence.
    /// This function is very greedy and should be used only if required, generally so as to reuse a FheString
    /// output as an input to a secondary processing.
    ///
    /// Note: use of nested parallelisation.
    pub fn make_reusable(&self, fhe_string: &FheString) -> FheString {

        // panic if already reusable
        assert!(!fhe_string.is_reusable(), "Calling make_reusable on an already reusable FheString object!");
        
        let len = fhe_string.len();
        let n_blocks = ServerKey::compute_blocks_for_len(len as u64);

        // first, compute which characters are not null characters, and extend the result
        // to the required number of blocks to be able to sum up
        let mut res_vec: Vec<RadixCiphertext> = fhe_string.fhe_chars().par_iter().map(
            |fhe_char|{
                let mut res = self.key.scalar_ne_parallelized(fhe_char.unwrap(), 0u8).into_radix(1, &self.key);
                // extend to the appropriate number of blocks if necessary
                if n_blocks > NUMBER_OF_BLOCKS{
                    self.key.extend_radix_with_trivial_zero_blocks_msb(&mut res, n_blocks - NUMBER_OF_BLOCKS);
                }
                res                
        }).collect();

        // then, let's associate each nth non null character with the index n in nth_indices
        // this is a cumulated sum of res_vec, necessarily sequential
        let mut nth_indices = Vec::<RadixCiphertext>::with_capacity(len);
        nth_indices.push(res_vec[0].clone());

        for i in 1..len {
            nth_indices.push( self.key.add_parallelized(&res_vec[i], &nth_indices[i-1]) );
        }

        // Now, we can querry the value of each nth non null character with sum( (nth_indices==n) * fhe_chars)
        // and assign it to the (n-1)th value of our tidy FheString (n-1 because we start at 0)
        // let's use a nested parallelization for faster computation
        let tidy_vec = (1..=len).into_par_iter().map(
         | n |{

            // first fill a vector with (nth_indices==n) * fhe_chars to be summed up
            // start at index n-1 because we cannot find nth_index==n below n-1
            let to_add_vec : Vec::<RadixCiphertext> = nth_indices[n-1..len].par_iter().enumerate().map(
                |(index, number)| {
                 // index is in range 0..len-n-1, so real_index = index+n-1 is in range n-1..len as we want
                 let real_index = index+n-1;
                 let is_equal_n = self.key.scalar_eq_parallelized(number, n as u64);
                 self.key.mul_parallelized(fhe_string.fhe_chars()[real_index].unwrap(), &is_equal_n.into_radix(1, &self.key))
            }).collect();     

            // sum the vec to get the value
            to_add_vec.into_par_iter().reduce(
                || self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
                |acc: RadixCiphertext, ele: RadixCiphertext| {
                    self.key.add_parallelized(&acc, &ele)
            })
        }).collect();

        // now, create a reusable and padded FheString from res_vec and return it
        FheString::from_encrypted(tidy_vec, true, true)
    }    


    /// Shifts and encrypted FheString to the left, removing the n first characters and putting \0 at the end
    /// Example: left_shift( '---abc', [0,0,0,1,0,0] ) gives 'abc\0\0\0'
    /// This function is very greedy (but less than ServerKey::make_reusable) and should be used only if required,
    /// so as to reuse a FheString output as an input to a secondary processing.
    ///
    /// Note: use of nest parallelisation.
    ///
    /// `vec_index` a Vec containing a one where we want the shifted result to start at (if no one, the result is unchanged)
    /// this vector may have a smaller length than fhe_string if we know for sure the one is present in this part
    /// `max_index` a Vec containing a one where we want the shifted result to start at (if no one, the result is unchanged)
    pub (crate) fn left_shift(&self, fhe_string: &FheString, vec_index: &Vec<RadixCiphertext>, is_reusable: bool) -> FheString {
        // return if empty
        if fhe_string.len()==0 {
            return fhe_string.clone();
        }
        let len = fhe_string.len();

        // Each character will be a boolean sum of all following characters multiplied by the values in vec_index
        let shifted_vec = (0..len).into_par_iter().map(
            | n |{
                let max_index = cmp::min(len, n+vec_index.len());

                // create the vec of values to be summed for this character
                let to_add_vec : Vec::<RadixCiphertext> = (n..max_index).into_par_iter().map(
                    |index|  self.key.mul_parallelized(fhe_string.fhe_chars()[index].unwrap(), &vec_index[index-n])
                ).collect();

                // sum the vec to get the non zero value
                to_add_vec.into_par_iter().reduce(
                    || self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
                    |acc: RadixCiphertext, ele: RadixCiphertext| {
                        self.key.add_parallelized(&acc, &ele)
            })
        }).collect();

        // now, create a FheString that may have padding from shifted_vec and return it
        FheString::from_encrypted(shifted_vec, true, is_reusable)
    }    

    /// Compute if_then_else for all values of two fhe_strings, and extend the result with trivial zeros to match the size
    fn if_then_else_fhe_string(
        &self,
        condition: &RadixCiphertext,
        fhe_str_1: &FheString,
        fhe_str_2: &FheString
    )-> FheString {
        let bool_condition = BooleanBlock::convert::<RadixCiphertext>(&condition, &self.key);
        assert!(fhe_str_1.is_encrypted() && fhe_str_2.is_encrypted(), "both fhe_strings should be encrypted");
        let zero_cst = self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
        let values: Vec<RadixCiphertext> = (0..cmp::max(fhe_str_1.len(),fhe_str_2.len())).into_par_iter().map(
            |index|{
                if index >= fhe_str_1.len(){
                    self.key.if_then_else_parallelized(
                        &bool_condition,
                        &zero_cst,
                        fhe_str_2.fhe_chars()[index].unwrap()
                    )
                }else if index >= fhe_str_2.len(){
                    self.key.if_then_else_parallelized(
                        &bool_condition,
                        fhe_str_1.fhe_chars()[index].unwrap(),
                        &zero_cst
                    )
                }else{
                    self.key.if_then_else_parallelized(
                        &bool_condition,
                        fhe_str_1.fhe_chars()[index].unwrap(),
                        fhe_str_2.fhe_chars()[index].unwrap()
                    )
                }
            }
        ).collect();
        FheString::from_encrypted(
            values,
            fhe_str_1.is_padded() || fhe_str_2.is_padded(),
            fhe_str_1.is_reusable() && fhe_str_2.is_reusable()
        )
    }        
}

// the implementation is split within the following module files:
mod contains;
mod partial_ordering;
mod case;
mod trim;
mod split;
mod replace;
mod repeat;