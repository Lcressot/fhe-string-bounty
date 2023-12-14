//! ServerKey implementation of replace and replacen functions for ciphertext::FheString objects

use tfhe::integer::ciphertext::{RadixCiphertext, IntegerCiphertext};
use rayon::prelude::*;

use crate::ciphertext::{FheString, FheAsciiChar};

use super::ServerKey;

use crate::NUMBER_OF_BLOCKS;


impl ServerKey {

	/// Extract RadixCipherText values of a FheString, encrypting them if they are clear
	fn get_encrypted_values(&self, fhe_string: &FheString) -> Vec<RadixCiphertext>{
		match fhe_string.is_encrypted(){
	     	true => fhe_string.fhe_chars().iter().map(|fhe_char| fhe_char.unwrap().clone()).collect(),
     		false => fhe_string.trivial_encrypt(&self.key, 0).fhe_chars().iter().map(|fhe_char| fhe_char.unwrap().clone()).collect()
     	}
	}

	/// Compute if_then_else for all values of two vectors, and extend the result with trivial zeros to match the size
	fn if_then_else_vec(
		&self,
		condition: &RadixCiphertext,
		vec_1: &Vec<RadixCiphertext>,
		vec_2: &Vec<RadixCiphertext>)
	-> Vec<RadixCiphertext>{
		let zero_cst = self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS);
		(0..vec_1.len().max(vec_2.len())).into_par_iter().map(
			|index|{
				if index >= vec_1.len(){
					self.key.if_then_else_parallelized(condition, &zero_cst, &vec_2[index])
				}else if index >= vec_2.len(){
					self.key.if_then_else_parallelized(condition, &vec_1[index], &zero_cst)
				}else{
					self.key.if_then_else_parallelized(condition, &vec_1[index], &vec_2[index])
				}
			}
		).collect()
	}

	/// Replace general implementation for FheStrings
	/// `replacen`: wether to replacen or replace
	/// `n_times`: count parameter for replacen
	fn replace_or_replacen(
			&self,
			fhe_string: &FheString,
			from: &FheString,
			to: &FheString,
			replacen: bool,
			n_times: usize
		) -> FheString {

		let msg = match replacen {
			true => "replacen",
			false => "replace"
		};

        // make sure the inputs are reusable:
        ServerKey::assert_is_reusable(fhe_string, msg);
        ServerKey::assert_is_reusable(from, msg);
        ServerKey::assert_is_reusable(to, msg);

        // 0. Trivial results

        if !from.is_padded() && from.len() > fhe_string.len() {
        	// if the from is not padded and is strictly longer than the string
        	// it cannot be contained in it
            return fhe_string.clone();
        }    

        // all inputs are clear
        if !fhe_string.is_encrypted() && !from.is_encrypted() && !to.is_encrypted() {
        	let replaced = if replacen {
        		fhe_string.to_string().replacen(&from.to_string().as_str(), &to.to_string().as_str(), n_times)
        	}else{
				fhe_string.to_string().replace(&from.to_string().as_str(), &to.to_string().as_str())
        	};
        	return FheString::from_string(&replaced);
        } 
                

        // Now we know that one of the inputs is encrypted, we need to work in FHE
        // four scenarios (I, II, III and IV) are possible:

        // I.a very easy scenario: the fhe_string and the from are both unencrypted, but to is encrypted
        // We can simply split fhe_string with "from" pattern in clear, then trivially encrypt and
        // concatenate with the encrypted "to" pattern
        if !fhe_string.is_encrypted() && !from.is_encrypted(){
        	let mut string = fhe_string.to_string();
        	let from_string = from.to_string();

		    // split the string with the "from" pattern
		    let sub_strings: Vec<String> = if replacen {
		    	string.splitn(n_times+1, &from_string).map(|str| str.to_string()).collect()
		    }else{
		    	string.split(&from_string).map(|str| str.to_string()).collect()
		    };

		    // and simply encrypt sub strings and concatenate them with the "to" pattern
		    let mut concatenation = Vec::<RadixCiphertext>::with_capacity(string.len()+to.len()*(sub_strings.len()-1));
		    (0..sub_strings.len()).into_iter().for_each(
		     |index|{
		     	// encrypt sub string
		     	let mut enc_sub_str_vec = sub_strings[index].chars().map(
		     			|c| self.key.create_trivial_radix(c as u8, NUMBER_OF_BLOCKS)
		     		).collect();
		     	// append it
		     	concatenation.append(&mut enc_sub_str_vec);
		     	// if not last, index, append the "to" pattern
		     	if !(index == sub_strings.len()-1){
		     		let mut to_occurence = to.fhe_chars().iter().map(|fhe_char| fhe_char.unwrap().clone()).collect();
		     		concatenation.append(&mut to_occurence);
		     	}
		     });

		    return FheString::from_encrypted(concatenation, to.is_padded(), !to.is_padded());
        }

        // I.b The string is empty and non padded 
        if fhe_string.len()==0 {
            if replacen && n_times == 0 {
                return fhe_string.clone();
            }else{
                if from.len() == 0{
                	return to.clone();
                }else{
                	if !from.is_padded(){
                		if from.is_clear(){
                			return FheString::from_str("");
                		}else{
                			return FheString::empty_encrypted();
                		}
                	}else{
                		// "from" pattern might be an empty string with padding
                		let is_empty_from = self.is_empty(from);
                		let empty_string = FheString::empty_encrypted();
                		let to_encrypted = if to.is_encrypted(){
                			to.clone()
                		}else{
                			to.trivial_encrypt(&self.key, 0)
                		};
                		// return either "to" or an empty string depending on if from is empty
                		return self.if_then_else_fhe_string(&is_empty_from, &to_encrypted, &empty_string);
                	}
                }
            }      
        }           

        // II., III. and IV. Next three scenarios require to compute the result in the case
        // where "from" is the empty string "" with padding

  	
	    let result_from_empty: Vec<RadixCiphertext> = if from.is_padded() || from.len()==0 {
        	let res = if to.len() == 0{
        		self.get_encrypted_values(fhe_string)
        	}else{
	        	// We need to concatenate copies of "to" patterns with every non null characters of fhe_string

		        // get values of the "to" pattern, ecnrypt them if required
		     	let to_values = self.get_encrypted_values(to);
		        // get values of the fhe_string, encrypt them if required
		     	let mut fhe_string_values = self.get_encrypted_values(fhe_string);
		     	fhe_string_values.reverse();

		     	let i_lt_len: Vec<RadixCiphertext> = if fhe_string.is_padded() {
		     		let len = self.len(fhe_string);
		     		let mut vec: Vec<RadixCiphertext> = (0..fhe_string.len()).into_par_iter().map(
				    	|index|{
				    		let mut res = self.key.scalar_gt_parallelized(&len, index as u64);
				    		self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut res, NUMBER_OF_BLOCKS-1);
				    		res
				    	}
			    	).collect();
			    	let mut last_value = self.make_trivial_bool(!replacen);
			    	self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut last_value, NUMBER_OF_BLOCKS-1);
			    	vec.push(last_value);
			    	vec
		     	}else{
		     		Vec::<RadixCiphertext>::new() // unused
		     	};

		     	let mut replaced_values = Vec::<RadixCiphertext>::with_capacity(to.len()*(fhe_string.len()+1)+fhe_string.len());
		     	let mut count=0;
		     	for i in 0..=fhe_string.len(){
		     		count+=1;	     		
		     		if !replacen || (count <= n_times){
		    			// if fhe_string.is_padded() and i >= fhe_string.len()
		    			// we need to push an empty string instead of to
			     		let mut to_or_zero = if fhe_string.is_padded(){
				     		(0..to.len()).into_par_iter().map(
				     			|index| self.key.mul_parallelized(&i_lt_len[i], &to_values[index])
				     		).collect()
			     		}else{
			     			to_values.clone()
			     		};

	     				replaced_values.append(&mut to_or_zero);
	     			}

	     			if i < fhe_string.len(){
			     		match fhe_string_values.pop(){
			     			Some(value) => replaced_values.push(value),
			     			None => panic!("should never happen")
			     		};
			     	}
		     	}
		     	replaced_values
		    };
		    res
        }else{
        	Vec::<RadixCiphertext>::new() // unused
        };


	 	// II. the special case where "from" is the empty string ""  with no padding     	
       	if from.len() == 0 {
	     	let is_padded = to.is_padded() || fhe_string.is_padded();
	     	return FheString::from_encrypted(result_from_empty, is_padded, !is_padded);
       	}          

        // III. and IV. Next two scenarios require to first compute contains_at_index_vec
        // and process it so as to prevent overlapping patterns
        let mut contains_at_index_vec = self.contains_at_index_vec(fhe_string, from);

        // extend contains_at_index_vec with to match the size of fhe_string in case it was made shorter
        // for speed of computation purpose
        if fhe_string.len()-contains_at_index_vec.len() > 0{
            let zero_cst = self.make_trivial_bool(false);
            let mut padding_vec = vec![zero_cst; fhe_string.len()-contains_at_index_vec.len()];
            contains_at_index_vec.append(&mut padding_vec);        
        }
        // and add one more 0 value, needed for some special cases in the following algorithm
        contains_at_index_vec.push(self.make_trivial_bool(false));

        let mut len = contains_at_index_vec.len();
 		let n_blocks = ServerKey::compute_blocks_for_len( len as u64);
        let mut from_true_length = self.len(from);
        
        if from_true_length.blocks().len() < n_blocks {
            let diff_blocks = n_blocks-from_true_length.blocks().len();
            self.key.extend_radix_with_trivial_zero_blocks_msb_assign(
                &mut from_true_length,
                diff_blocks
            );
        }

        let mut pattern_start_index = self.key.create_trivial_zero_radix(n_blocks);
        let mut first_one_seen = self.make_trivial_bool(false); // wether we encountered the first one
        let mut pattern_started = self.make_trivial_bool(false);

        let mut is_pattern_vec =  Vec::<RadixCiphertext>::with_capacity(fhe_string.len()); // record where the pattern is

        let mut sum_pattern_starts = self.key.create_trivial_zero_radix(n_blocks);

        // this is iterative, it cannot be parallelized
        for index in 0..len {

	  		// compute wether it is the first one
	        // and
	        // check the pattern ended and whether it just ended
	        // This is required to prevent the pattern overlapping problems
	        // for instance "ababababababab".split("abab") will have contains_at_index_vec like "0101010101.."
	        // with the pattern overlapping itself

	        let not_first_one_seen = self.not(&first_one_seen);
	        let (is_first_one, pattern_start_index_plus_pattern_length) = rayon::join(
	            || self.key.bitand_parallelized(&contains_at_index_vec[index], &not_first_one_seen),
	            || self.key.add_parallelized(&pattern_start_index, &from_true_length)
	        );

	        let (mut not_pattern_just_ended, mut pattern_ended) = rayon::join(
                || self.key.scalar_ne_parallelized(&pattern_start_index_plus_pattern_length, index as u64),
                || self.key.scalar_le_parallelized(&pattern_start_index_plus_pattern_length, index as u64)
            );

	        // this value only makes sense if a pattern has started already	        
	        self.key.bitand_assign_parallelized(&mut pattern_ended, &first_one_seen);

	        // udpate pattern_start_index
	        // a new pattern starts if we have a first one or a one with pattern_ended
	        let one_and_pattern_ended = self.key.bitand_parallelized(&contains_at_index_vec[index], &pattern_ended);
	        let pattern_starts = self.key.bitor_parallelized(&is_first_one, &one_and_pattern_ended);
	        let encrypted_index = self.key.create_trivial_radix(index as u64, n_blocks);
	        pattern_start_index = self.key.if_then_else_parallelized(&pattern_starts, &encrypted_index, &pattern_start_index);

        	// update pattern_started and not_pattern_just_ended
        	// and
        	// // update pattern_started and update first_one_seen for next iteration
        	(_, _) = rayon::join(
            	|| self.key.bitor_assign_parallelized(&mut pattern_started, &pattern_starts),
            	|| self.key.bitor_assign_parallelized(&mut not_pattern_just_ended, &pattern_starts)
            );

            (_, _) = rayon::join(
	            || self.key.bitand_assign_parallelized(&mut pattern_started, &not_pattern_just_ended),
				|| self.key.bitor_assign_parallelized(&mut first_one_seen, &contains_at_index_vec[index])
			);

	        // update contains_at_index_vec so as to erase ones corresponding to overlapping patterns
	        // keep a one only if pattern has not ended	

	        if replacen{
	        	let pattern_starts_extended = self.key.extend_radix_with_trivial_zero_blocks_msb(&pattern_starts, n_blocks-1);
	        	self.key.add_assign_parallelized(&mut sum_pattern_starts, &pattern_starts_extended);
	        	let sum_pattern_starts_le_n = self.key.scalar_le_parallelized(&sum_pattern_starts, n_times as u64);

	        	let (pattern_starts_n, pattern_started_n) = rayon::join(
	        		|| self.key.bitand_parallelized(&sum_pattern_starts_le_n, &pattern_starts),
	        		|| self.key.bitand_parallelized(&sum_pattern_starts_le_n, &pattern_started)
	        	);

                contains_at_index_vec[index] = pattern_starts_n;
                is_pattern_vec.push(pattern_started_n);
	        }else{
    	        contains_at_index_vec[index] = pattern_starts;
                is_pattern_vec.push(pattern_started.clone());
	        }
	    }

        // III. easy scenario: the "from" pattern has a greater or equal real length than the "to" pattern
        // We can simply pad the "to" pattern to match the size of the "from" pattern and write
        // the "to" pattern where we found the "from" pattern. This requires that the from pattern is not padded
        if !from.is_padded() && from.len() >= to.len(){
        	// wherever there is a one in contains_at_index_vec, we will write the "to" pattern
        	// and erase the remaining content of the "from" pattern with empty characters

        	// first, clone the "to" pattern and pad it to match the size of the "from" pattern        	
        	let to_fhe_padded = if to.is_encrypted(){
				let mut to_padded = to.clone();
				to_padded.pad(from.len() - to.len(), &self.key); // nothing happens if the sizes are equal
				to_padded
        	}else{
        		to.trivial_encrypt(&self.key, from.len() - to.len())
        	};

   	
        	// now write values of the "to" pattern in the fhe_string where there is one in contains_at_index_vec

            // extend all values in contains_at_index_vec to 8 bits
            for i in 0..contains_at_index_vec.len() {
            	self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut contains_at_index_vec[i], NUMBER_OF_BLOCKS-1)
            }


        	// start by writting the values of the "to" pattern in an empty vector by summing.
			let pattern_replaced: Vec<RadixCiphertext> = (0..fhe_string.len()).into_par_iter().map(
				| n |{
			        // create the vec of values to be summed for this character
			        let start_index = if n >= to_fhe_padded.len() { n-to_fhe_padded.len()+1 } else { 0 };
			        let to_add_vec : Vec::<RadixCiphertext> = (0..=n-start_index).into_iter().map(
			            |index| {
		            		self.key.mul_parallelized(
		            			&contains_at_index_vec[n-index],
		            			to_fhe_padded.fhe_chars()[index].unwrap()
		            		)
			        }).collect();

			        // sum the vec to get the non zero value
			        to_add_vec.into_par_iter().reduce(
			            || self.key.create_trivial_zero_radix(NUMBER_OF_BLOCKS),
			            |acc: RadixCiphertext, ele: RadixCiphertext| {
			                self.key.add_parallelized(&acc, &ele)
			        })
			}).collect();


			// Then, simply chose between values in fhe_string values and pattern_replaced
			// depending on if the pattern is present or not at the index
			let replaced_values = (0..fhe_string.len()).into_par_iter().map(
				|index|{
					if fhe_string.is_encrypted(){
						self.key.if_then_else_parallelized(
							&is_pattern_vec[index],
							&pattern_replaced[index],
							fhe_string.fhe_chars()[index].unwrap(),
						)
					}else{
						self.key.if_then_else_parallelized(
							&is_pattern_vec[index],
							&pattern_replaced[index],
							&self.key.create_trivial_radix(fhe_string.chars()[index] as u8, NUMBER_OF_BLOCKS),
						)
					}
				}
			).collect();



			// Now, if "from" is padded, it may be empty, so we need to chose between
			// our result and the one we computed earlier
			let from_is_empty = self.is_empty(from);
			let final_values: Vec<RadixCiphertext> = if from.is_padded(){
				self.if_then_else_vec(&from_is_empty, &result_from_empty, &replaced_values)
			}else{
				replaced_values
			};


        	return FheString::from_encrypted(
        		final_values,
        		// Note: if from happens to be empty but padded with (from.len() > to.len()), the result
        		// may not be padded after all, but it will me marked as padded
        		fhe_string.is_padded() || (from.len() > to.len()) || to.is_padded(),
        		from.len() == to.len() && !to.is_padded()
        	);
        }
        // IV. harder scenario: the "from" pattern has shorter length than the "to" pattern or the "from" pattern
        // is padded, and may have a real shorter length than the "to" pattern.
        // Here, the "to" pattern does not fit inside where the "from" pattern was.
        // So, we are forced to split the fhe_string with "from" pattern, then make concatenations
        // with the "to" pattern, as we did in sceneario I., but we will leave a huge amount of empty
        // characters inside the result string here.
        else{        	
		    // split the string with the "from" pattern (the will be necessarily enrypted here)
		    let (mut sub_strings, number_of_fields, from_is_empty) = if replacen {
		    	self.splitn_pattern_empty(n_times+1, fhe_string, from)
		    }else{
		    	self.split_pattern_empty(fhe_string, from)
		    };

	        // get values of the "to" pattern, ecnrypt them if required
	     	let to_encrypted_values = self.get_encrypted_values(to);

		    // and simply concatenate them with the "to" pattern
		    let mut to_concatenate = Vec::<FheString>::new();

		    let to_or_zero: Vec<Vec<RadixCiphertext>> = (0..sub_strings.len()-1).into_par_iter().map(
		    	|index|{
		    		let mut index_lt_number_of_fields = self.key.scalar_gt_parallelized(&number_of_fields, (index+1) as u64);
		    		self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut index_lt_number_of_fields, NUMBER_OF_BLOCKS-1);
		    		(0..to.len()).into_par_iter().map(
		     			|sub_index| self.key.mul_parallelized(&index_lt_number_of_fields, &to_encrypted_values[sub_index])
		     		).collect()
		    }).collect();
		    
		    sub_strings.reverse();
		    let sub_strings_len = sub_strings.len();
		    for index in 0..sub_strings_len {
		     	// append it		     	
		     	let mut sub_str = match sub_strings.pop(){
		     		Some(sub_str) => sub_str,
		     		None => panic!("Should not happen")
		     	};
		     	to_concatenate.push(sub_str);
		     	// push the "to" pattern except at the end
		     	if index < sub_strings_len-1 {
		     		// if i >= number_of_fields, we need to push an empty string instead of to
		     		to_concatenate.push(FheString::from_encrypted(to_or_zero[index].clone(), true, true));		     		
		     	}
		    }

		    // TODO: improve this to avoid cloning too much values
		    let concatenated_string = FheString::concatenate(&to_concatenate);
		   	let concatenated_values = self.get_encrypted_values(&concatenated_string);

			// Now, if "from" is padded, it may be empty, so we need to chose between
			// our result and the one we computed earlier
			let final_values: Vec<RadixCiphertext> = if from.is_padded(){
				self.if_then_else_vec(&from_is_empty, &result_from_empty, &concatenated_values)
			}else{
				concatenated_values
			};

        	return FheString::from_encrypted(final_values, true, false);
        }
        
	}

	/// Replace implementation for FheStrings
	pub fn replace(&self, fhe_string: &FheString, from: &FheString, to: &FheString) -> FheString {
		// reusability of inputs is checked inside replace_or_replacen
		self.replace_or_replacen(fhe_string, from, to, false, 0)
	}

    /// Replace implementation for FheStrings that produce a reusable FheString
    /// Note: This function does not require that the FheString is reusable
    pub fn replace_reusable(&self, fhe_string: &FheString, from: &FheString, to: &FheString) -> FheString {        
        let replaced_string = self.replace(fhe_string, from, to);

        // replace the string and make it reusable
        if !replaced_string.is_reusable(){
        	self.make_reusable(&replaced_string)
        }else{
        	replaced_string
        }        
    }  	

	/// Replacen implementation for FheStrings
	pub fn replacen(&self, fhe_string: &FheString, from: &FheString, to: &FheString, count: usize) -> FheString {
		// reusability of inputs is checked inside replace_or_replacen
		self.replace_or_replacen(fhe_string, from, to, true, count)
	}

    /// Replacen implementation for FheStrings that produce a reusable FheString
    /// Note: This function does not require that the FheString is reusable
    pub fn replacen_reusable(&self, fhe_string: &FheString, from: &FheString, to: &FheString, count: usize) -> FheString {        
        let replaced_string = self.replacen(fhe_string, from, to, count);

        if !from.is_padded() && !to.is_padded() && from.len()==to.len() {
            // no need to make reusable here
            return replaced_string;
        }
        // replace the string and make it reusable
        if !replaced_string.is_reusable(){
        	self.make_reusable(&replaced_string)
        }else{
        	replaced_string
        }   
    }  	


}