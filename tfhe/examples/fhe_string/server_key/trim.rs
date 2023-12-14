//! ServerKey implementation of trimming and stripping functions for ciphertext::FheString objects

use tfhe::integer::ciphertext::{RadixCiphertext, IntegerCiphertext};
use rayon::prelude::*;
use std::cmp;

use crate::ciphertext::{FheString, FheAsciiChar};
use crate::NUMBER_OF_BLOCKS;

use super::ServerKey;

impl ServerKey{

	/// Compute wether characters of a FheString are whitespaces (' ', '\n' or '\t')
    pub (crate) fn is_whitespace(&self, fhe_string: &FheString) -> Vec::<RadixCiphertext> {
    	
    	let eq_char = | character: char | {
			self.apply_parallelized_vec(
	            fhe_string.fhe_chars(),
	            |c: &FheAsciiChar| self.key.scalar_eq_parallelized(c.unwrap(), character as u8)
	        ) 		
    	};

        let (eq_space, (eq_backslash_t_, eq_backslash_n) ) = rayon::join(
        	|| eq_char(' '),
        	|| rayon::join(
        		|| eq_char('\n'),
        		|| eq_char('\t')
        	)
        );

        (0..fhe_string.len()).into_par_iter().map(
        	|index|{
        		let mut res = self.key.bitor_parallelized(&eq_backslash_n[index], &eq_backslash_t_[index]);
        		self.key.bitor_assign_parallelized(&mut res, &eq_space[index]);
        		res
        }).collect()
    }

    /// Given a boolean vector `is_whitespace` containing wether values are whitespaces or not,
    /// keep only to one the values that are one and are at the start, and put them in `is_whitespace_mut`
    fn keep_starting_whitespaces_only(&self, is_whitespace: &Vec<RadixCiphertext>) -> Vec<RadixCiphertext>{
    	let mut only_ones_before = self.make_trivial_bool(true);
    	// this is iterative, it cannot be parallelized
        (0..is_whitespace.len()).into_iter().map(
        	|index|{
        		self.key.bitand_assign_parallelized(&mut only_ones_before, &is_whitespace[index]);
        		only_ones_before.clone()
        	}
        ).collect()   	
    }

    /// Given a boolean vector containing wether values are whitespaces or not, and a FheString,
    /// keep only to one the values that are at the end and either one or null characters in the FheString
    fn keep_ending_whitespaces_only(&self, fhe_string: &FheString, is_whitespace: &Vec<RadixCiphertext>) -> Vec<RadixCiphertext>{
        // then, keep only the is_whitespace to one if they are at the end (or if empty character), or put them to zero
        // this needs to be sequential

	    let len = fhe_string.len();

	    let mut res: Vec::<RadixCiphertext> = match fhe_string.is_padded(){
	    	false => {
		    	// if the fhe_string does not have padding, we don't need to account for possible trailing \0 values
		    	// this is iterative, it cannot be parallelized
		        let mut only_ones_after = self.make_trivial_bool(true);
		        (0..len).into_iter().map(
		        	|index|{
		        		self.key.bitand_assign_parallelized(&mut only_ones_after, &is_whitespace[len-1-index]);
		        		only_ones_after.clone()
		        	}
		        ).collect()
	    	},
	    	true => {
		    	// if the fhe_string may have padding, we need to account for possible trailing \0 values

		    	// compute if values are zero:
	        	let is_zero = self.apply_parallelized_vec(
	            	fhe_string.fhe_chars(),
	            	|c: &FheAsciiChar| self.key.scalar_eq_parallelized(c.unwrap(), 0u8)
	            );

	        	// fill is_whitespace with ones for the ending padding values and whitespace characters' indices
	        	// this is iterative, it cannot be parallelized
		        let mut only_ones_after = self.make_trivial_bool(true);
		        (0..len).into_iter().map(
		        	|index|{
		        		let mut boolean = is_whitespace[len-1-index].clone();
		        		self.key.bitor_assign_parallelized(&mut boolean, &is_zero[len-1-index]);
		        		self.key.bitand_assign_parallelized(&mut only_ones_after, &boolean);
		        		only_ones_after.clone()
		        	}
		        ).collect()
	    	}
	    };
	    res.reverse(); // reverse as we used len-1-index instead of index
        res
    }    

    /// Trim whitespace characters (' ', '\t' and '\n') from the start of a FheString object
    /// If reusable is true, the result will be shifted so that the starting characters are not empty
    /// `is_whitespace` a mut Vec<RadixCiphertext> indicating where whitespaces are
    fn trim_start_reusable_or_not_vec(&self, fhe_string: &FheString, reusable: bool, mut is_whitespace: Vec<RadixCiphertext>) -> FheString{
		let len = fhe_string.len();

     	if !reusable{
	        // keep only the is_whitespace to one if they are at the start, or put them to zero
	        let is_starting_whitespace = self.keep_starting_whitespaces_only(&is_whitespace);
       		
    		// and keep the letters where the is_whitespace is false
 			let res_vec = self.set_zero_where(fhe_string, &is_starting_whitespace);
 			return FheString::from_encrypted(res_vec, fhe_string.is_padded(), len == 0 );
 		}else{
 			// If reusable is true, we need to shift all values, this is computationally heavy

 			// mark a one where the is_whitespace has a first 0
 			// which means where there is the first non whitespace character
			// this is iterative, it cannot be parallelized    			
	        let mut only_ones_before = self.make_trivial_bool(true);
	        (0..len).into_iter().for_each(
	        	|index|{
	        		let only_ones_before_save = only_ones_before.clone();
        			self.key.bitand_assign_parallelized(&mut only_ones_before, &is_whitespace[index]);
        			is_whitespace[index] = self.key.ne_parallelized(&only_ones_before, &only_ones_before_save);
        		}
    		);

    		// now, is_whitespace has either only a one where the non whitespaces characters begin
    		// or it has only zeros which means the sequence is entirely made of whitespace characters
    		// We can shift the FheString to the left with self.left_shift to remove the starting whitespaces
    		// and make the output tidy and reusable
    		return self.left_shift(fhe_string, &is_whitespace, fhe_string.is_reusable());
 		}
    }

    /// Trim whitespace characters (' ', '\t' and '\n') from the start of a FheString object
    /// Warning: Requires reusable FheString
    /// `reusable` if true, the result will be shifted so that the starting characters are not empty
    fn trim_start_reusable_or_not(&self, fhe_string: &FheString, reusable: bool) -> FheString{
        // make sure the FheString is tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"trim_start_reusable_or_not");

    	// if the FheString is clear:
    	if !fhe_string.is_encrypted(){    		
    		let string = fhe_string.to_string().trim_start().to_string();
    		return FheString::from_string(&string);
    	}

    	// else, it is encrypted:

    	// first, compute wether characters are either ' ', '\n' or '\t'
        let mut is_whitespace = self.is_whitespace(fhe_string);

	    self.trim_start_reusable_or_not_vec(fhe_string, reusable, is_whitespace)
    }

    /// Trim whitespace characters (' ', '\t' and '\n') from the start of a FheString object
	/// Warning: Requires reusable FheString    
    /// Warning: the result will be not tidy (i.e. containing non ending null values)
    pub fn trim_start(&self, fhe_string: &FheString) -> FheString{
        // make sure the FheString is tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"trim_start");

        // the result will not be tidy
        self.trim_start_reusable_or_not(fhe_string, false)
    }

    /// Trim whitespace characters (' ', '\t' and '\n') from the start of a FheString object
    /// And shift the characters so that the starting characters are not empty
    /// This makes the result reusable, but computationally heavy to produce
	/// Warning: Requires reusable FheString    
    pub fn trim_start_reusable(&self, fhe_string: &FheString) -> FheString{
        // make sure the FheString is tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"trim_start_reusable");

        // the result will be tidy
        self.trim_start_reusable_or_not(fhe_string, true)
    }    

    /// Trim whitespace characters (' ', '\t' and '\n') from the end of a FheString object
	/// Warning: Requires reusable FheString    
    pub fn trim_end(&self, fhe_string: &FheString) -> FheString{
        // make sure the FheString is tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"trim_end");

    	// if the FheString is clear:
    	if !fhe_string.is_encrypted(){    		
    		let string = fhe_string.to_string().trim_end().to_string();
    		return FheString::from_string(&string);
    	}

    	// else, it is encrypted:

    	// first, compute wether characters are either ' ', '\n' or '\t'
        let mut is_whitespace = self.is_whitespace(fhe_string);

        // then, keep only the is_whitespace to one if they are at the end (or if empty character), or put them to zero
        // this needs to be sequential
	    let is_ending_whitespace = self.keep_ending_whitespaces_only(fhe_string, &is_whitespace);

        // then, keep the letters where the is_whitespace is false
     	let trimmed_vec = self.set_zero_where(fhe_string, &is_ending_whitespace);

		// now, create a tidy FheString that may have padding (except if len==0) from trimmed_vec and return it
		FheString::from_encrypted(trimmed_vec, true & (fhe_string.len() > 0), true)
    }


    /// Trim whitespace characters (' ', '\t' and '\n') from the start and end of a FheString object
    /// If reusable is true, the result will be shifted so that the starting characters are not empty
	/// Warning: Requires reusable FheString    
    pub fn trim_reusable_or_not(&self, fhe_string: &FheString, reusable: bool) -> FheString{    
        // make sure the FheString is tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"trim_reusable_or_not");

    	// if the FheString is clear:
    	if !fhe_string.is_encrypted(){    		
    		let mut string = fhe_string.to_string().trim().to_string();
    		return FheString::from_string(&string);
    	}

    	// else, it is encrypted:

    	// I. compute wether characters are either ' ', '\n' or '\t'
        let mut is_whitespace = self.is_whitespace(fhe_string);

        // II. keep only the is_whitespace to one if they are at the start or at the end, or put them to zero:

		//  1. compute wether there are ones at the end of is_whitespace
	   	let is_ending_whitespace = self.keep_ending_whitespaces_only(fhe_string, &is_whitespace);

	    //    and keep the letters where the is_ending_whitespace is false in trimmed_end_vec
     	let trimmed_end_vec = self.set_zero_where(fhe_string, &is_ending_whitespace);    

     	// 	  make a new string with trimmed end (it may have padding and is tidy):
     	let fhe_string_trimmed_end = FheString::from_encrypted(trimmed_end_vec, true, true);  

	    //  2. compute wether there are ones at the start of is_whitespace
	    let is_starting_whitespace = self.keep_starting_whitespaces_only(&is_whitespace);

	    //    and trim again at the start the trimmed fhe_string_trimmed_end FheString
	    self.trim_start_reusable_or_not_vec(&fhe_string_trimmed_end, reusable, is_starting_whitespace)
    }

    /// Trim whitespace characters (' ', '\t' and '\n') from the start and end of a FheString object
	/// Warning: the result will be not tidy (i.e. containing non ending null values)    
	/// Warning: Requires reusable FheString	
    pub fn trim(&self, fhe_string: &FheString) -> FheString{    
        // make sure the FheString is tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"trim");

        // the result will be not tidy
		self.trim_reusable_or_not(fhe_string, false)
    }

    /// Trim whitespace characters (' ', '\t' and '\n') from the start and end of a FheString object
    /// And shift the characters so that the starting characters are not empty
    /// This makes the result reusable, but computationally heavy to produce
	/// Warning: Requires reusable FheString    
    pub fn trim_reusable(&self, fhe_string: &FheString) -> FheString{    
        // make sure the FheString is reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"trim_reusable");

        // the result will be reusable
		self.trim_reusable_or_not(fhe_string, true)
    }    

    /// Trim FheString prefix from a FheString object
    /// Returns the result FheString and wether the prefix was present
	/// Warning: the result will be not tidy (i.e. containing non ending null values)
	/// Warning: Requires reusable FheStrings	
	/// Note: if the first string is clear and the second is encrypted, the output will be encrypted
    pub fn strip_prefix(&self, fhe_string: &FheString, pattern: &FheString) -> (FheString, RadixCiphertext){
        // make both are tidy first:
        ServerKey::assert_is_reusable(fhe_string, &"strip_prefix");
        ServerKey::assert_is_reusable(pattern, &"strip_prefix");

    	if !fhe_string.is_encrypted() && !pattern.is_encrypted(){
    		// if both are clear, the result is easy
    		let string_1 = fhe_string.to_string();
    		let string_2 = pattern.to_string();
    		let option = string_1.strip_prefix( &string_2 );
    		return match option{
    			Some(string) => (FheString::from_string(&string.to_string()), self.make_trivial_bool(true)),
    			None => (fhe_string.clone(), self.make_trivial_bool(false))
    		};
    	}

    	// trivial cases
    	if fhe_string.len()==0 {
    		return (fhe_string.clone(), self.is_empty(pattern))
    	}

    	if pattern.len()==0 {
    		return (fhe_string.clone(), self.make_trivial_bool(true))
    	}

    	// compute if fhe_string starts with pattern
    	let starts_with = self.starts_with(fhe_string, pattern);


    	let to_remove: Vec::<RadixCiphertext> = match pattern.is_padded() {
    		false => {
    			// if pattern has no padding, the index where the prefix would stop is clear

		    	if fhe_string.len() < pattern.len(){
		    		// if pattern is longer than fhe_string and pattern has no padding
		    		// then the suffix cannot be present
		    		return (fhe_string.clone(), self.make_trivial_bool(false));
		    	}

    			let shift_index = pattern.len();

    			// now fill a vector with ones where we want to remove the characters of the prefix
			    // avoid computing for values that cannot be part of the prefix with shift_index
		    	(0..shift_index).into_par_iter().map(
		    		|index| starts_with.clone() // don't remove anything if the prefix was not found	    			
		    	).collect() 			
    		},
    		true => {
    			// if pattern may have padding, the index where the prefix would stop is encrypted
				// get the index where the end of the prefix is (if the prefix is present)
		    	let shift_index = self.len(pattern);

		    	// now fill a vector with ones where we want to remove the characters of the prefix
		    	let visible_len = pattern.len();
		    	// avoid computing for values that cannot be part of the prefix with visible_len
		    	(0..visible_len).into_par_iter().map(
		    		|index|{
		    			let mut is_gt = self.key.scalar_gt_parallelized(&shift_index, index as u64);
		    			let n_blocks = is_gt.blocks().len()-1;
		    			self.key.trim_radix_blocks_msb_assign(&mut is_gt, n_blocks); // trim to one block
		    			self.key.bitand_parallelized(&is_gt, &starts_with) // don't remove anything if the prefix was not found
	    			}
		    	).collect()
    		}
    	};

    	// encrypt fhe_string if it is clear
    	let fhe_string_enc: FheString = match fhe_string.is_encrypted(){
    		true => fhe_string.clone(),
    		false => self.trivial_encrypt_fhe_string(fhe_string, 0)
    	};

    	// now we can set to zero the values of fhe_string_enc where to_remove is true
    	let mut striped_vec = self.set_zero_where_indices(&fhe_string_enc, &to_remove, 0, to_remove.len());

    	// extend striped_vec with the remaining values of fhe_string
    	for index in to_remove.len()..fhe_string_enc.len(){
    		striped_vec.push(fhe_string_enc.fhe_chars()[index].unwrap().clone());
    	}

    	// and return the non reusable FheString result
  		(FheString::from_encrypted(striped_vec, fhe_string_enc.is_padded(), false), starts_with)
    }

    /// Trim FheString prefix from a FheString object
    /// And shift the characters so that the starting characters are not empty
    /// This makes the result reusable, but computationally heavy to produce 
	/// Note: if the first string is clear and the second is encrypted, the output will be encrypted       
	/// Warning: Requires reusable FheStrings	
    pub fn strip_prefix_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (FheString, RadixCiphertext){
 		// make both are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"strip_prefix");
        ServerKey::assert_is_reusable(pattern, &"strip_prefix");

    	if !fhe_string.is_encrypted() && !pattern.is_encrypted(){
    		// if both are clear, the result is easy
    		let string_1 = fhe_string.to_string();
    		let string_2 = pattern.to_string();
    		let option = string_1.strip_prefix( &string_2 );
    		return match option{
    			Some(string) => (FheString::from_string(&string.to_string()), self.make_trivial_bool(true)),
    			None => (fhe_string.clone(), self.make_trivial_bool(false))
    		};
    	}

    	// trivial cases
    	if fhe_string.len()==0 {
    		return (fhe_string.clone(), self.is_empty(pattern))
    	}

    	if pattern.len()==0 {
    		return (fhe_string.clone(), self.make_trivial_bool(true))
    	}    	

    	// compute if fhe_string starts with pattern
    	let starts_with = self.starts_with(fhe_string, pattern);
    	// get the index where the end of the prefix would be if present
    	let shift_index = self.len(pattern);    	
    	// compute a vector with a one at index shift_index if starts_with is true, or at index 0 if starts_with is false
    	let visible_len = pattern.len();

    	let fhe_string_enc = if fhe_string.is_encrypted(){
    		FheString::empty_encrypted() // unused
    	}else{
    		fhe_string.trivial_encrypt(&self.key, 0)
    	};    	

		if !pattern.is_padded() {
			// if pattern has no padding, the index where the prefix would stop is clear
			let shift_index = pattern.len();

	    	if fhe_string.len() < pattern.len(){
	    		// if pattern is longer than fhe_string and pattern has no padding
	    		// then the suffix cannot be present
	    		return (fhe_string.clone(), self.make_trivial_bool(false));
	    	}    			
			// compute the shifted version of the string, if starts_with was true
			let mut shifted_string: FheString = fhe_string.sub_string(shift_index, fhe_string.len()-1);

			if shifted_string.is_clear(){
				shifted_string = shifted_string.trivial_encrypt(&self.key, 0);
			}
			// append padding to match the string length
			shifted_string.pad(fhe_string.len() - shift_index, &self.key);

			// and now chose between this version and the non shifted one given the condition start_with
			if fhe_string.is_encrypted(){
				return (self.if_then_else_fhe_string(&starts_with, &shifted_string, fhe_string),
						starts_with);
			}else{
				return (self.if_then_else_fhe_string(&starts_with, &shifted_string, &fhe_string_enc),
						starts_with);				
			}
		}else{
			// if pattern is padded, we want to know the index where we need to shift the values from
			// avoid computing for values that cannot be part of the prefix with visible_len
	    	let mut index_vec: Vec<RadixCiphertext> = (0..visible_len).into_par_iter().map(
	    		|index|{
	    			let mut is_eq = self.key.scalar_eq_parallelized(&shift_index, index as u64);
	    			let n_blocks = is_eq.blocks().len()-1;
	    			self.key.trim_radix_blocks_msb_assign(&mut is_eq, n_blocks); // trim to one block
	    			self.key.bitand_parallelized(&is_eq, &starts_with) // don't remove anything if the prefix was not found
	    	}).collect();			

	    	// if starts_with is false, we want the first element of index_vec to be true
	    	// which will keep the FheString unchanged by left_shift
	    	self.key.bitor_assign_parallelized(&mut index_vec[0], &self.not(&starts_with));

	    	// finally, left shift the result to remove the prefix characters
	    	if fhe_string.is_encrypted(){
		    	return (self.left_shift(fhe_string, &index_vec, fhe_string.is_reusable()),
		    			starts_with)
		    }else{
		    	return (self.left_shift(&fhe_string_enc, &index_vec, fhe_string.is_reusable()),
		    			starts_with)
		    }
    	}

    }    


    /// Trim FheString suffix from a FheString object
    /// Returns the result FheString and wether the suffix was present
	/// Warning: the result will be not reusable (i.e. containing non ending null values)
	/// Note: if the first string is clear and the second is encrypted, the output will be encrypted
	/// Warning: Requires reusable FheStrings	
    pub fn strip_suffix(&self, fhe_string: &FheString, pattern: &FheString) -> (FheString, RadixCiphertext){
        // make both are reusable first:
        ServerKey::assert_is_reusable(fhe_string, &"strip_suffix");
        ServerKey::assert_is_reusable(pattern, &"strip_suffix");

    	if !fhe_string.is_encrypted() && !pattern.is_encrypted(){
    		// if both are clear, the result is easy
    		let string_1 = fhe_string.to_string();
    		let string_2 = pattern.to_string();
    		let option = string_1.strip_suffix( &string_2 );
    		return match option{
    			Some(string) => (FheString::from_string(&string.to_string()), self.make_trivial_bool(true)),
    			None => (fhe_string.clone(), self.make_trivial_bool(false))
    		};
    	}

    	// trivial cases
    	if fhe_string.len()==0 {
    		return (fhe_string.clone(), self.is_empty(pattern))
    	}

    	if pattern.len()==0 {
    		return (fhe_string.clone(), self.make_trivial_bool(true))
    	}    	

    	// compute if fhe_string ends with pattern
    	let ends_with = self.ends_with(fhe_string, pattern);

		if fhe_string.len() < pattern.len() && !pattern.is_padded() {
    		// if pattern is longer than fhe_string and pattern has no padding
    		// then the suffix cannot be present
    		return (fhe_string.clone(), self.make_trivial_bool(false));
    	}

    	let to_remove = match !fhe_string.is_padded() && !pattern.is_padded() {
    		true =>{
    			// if both have no padding, the index of where the prefix would start is clear
		    	if fhe_string.len() < pattern.len(){
		    		// if pattern is longer than fhe_string and they both have no padding
		    		// then the suffix cannot be present
		    		return (fhe_string.clone(), self.make_trivial_bool(false));
		    	}
		    	// now we know that sufix_start_index will be >= 0
		    	let sufix_start_index = fhe_string.len() - pattern.len();

    			// now fill a vector with ones where we want to remove the characters of the suffix
			   	(0..fhe_string.len()).into_par_iter().map(
		    		|index|{
		    			// here we need to process all indices because we don't know how much padding there may be
		    			let mut is_le = self.make_trivial_bool(sufix_start_index <= index);
		    			let n_blocks = is_le.blocks().len()-1;
						self.key.trim_radix_blocks_msb_assign(&mut is_le, n_blocks); // trim to one block		    			
		    			self.key.bitand_parallelized(&is_le, &ends_with) // don't remove anything if the suffix was not found
		    	}).collect()
    		},
    		false =>{
    			// if one may have padding, the index of where the prefix would start is encrypted
		    	// get the index where the the suffix would start if present 
		    	let mut len_1 = self.len(fhe_string);
		    	let len_2 = self.len(pattern);	
		    	let mut conditional_len_2 = self.key.mul_parallelized(&len_2, &ends_with);
		    	self.extend_equally(&mut len_1, &mut conditional_len_2);
		    	let sufix_start_index = self.key.sub_parallelized(&len_1, &conditional_len_2);
		    	// note that if len_2 > len_1, then conditional_len_2 = 0 because ends_with is 0
		    	// so there is no way that sufix_start_index get to be negative

    			// now fill a vector with ones where we want to remove the characters of the suffix
			   	(0..fhe_string.len()).into_par_iter().map(
		    		|index|{
		    			// here we need to process all indices because we don't know how much padding there may be
		    			let mut is_le = self.key.scalar_le_parallelized(&sufix_start_index, index as u64);
		    			let n_blocks = is_le.blocks().len()-1;
						self.key.trim_radix_blocks_msb_assign(&mut is_le, n_blocks); // trim to one block
		    			self.key.bitand_parallelized(&is_le, &ends_with) // don't remove anything if the suffix was not found
		    	}).collect()
    		}

    	};

 
    	// encrypt fhe_string if it is clear
    	let fhe_string_enc: FheString = match fhe_string.is_encrypted() {
    		true => fhe_string.clone(),
    		false => self.trivial_encrypt_fhe_string(fhe_string, 0)
    	};

    	// now we can set to zero the values of fhe_string_enc where to_remove is true
    	let striped_vec = self.set_zero_where(&fhe_string_enc, &to_remove);

    	// and return the reusable FheString result (which may have padding)
  		(FheString::from_encrypted(striped_vec, true, true), ends_with)
    }    

}

