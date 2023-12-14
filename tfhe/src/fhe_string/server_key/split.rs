//! ServerKey implementation of trimming and stripping functions for ciphertext::FheString objects

use tfhe::integer::ciphertext::{RadixCiphertext, IntegerCiphertext};
use rayon::prelude::*;
use std::cmp;
use crate::ciphertext::{FheString};

use super::ServerKey;
use crate::NUMBER_OF_BLOCKS;

impl ServerKey{

    /// Left shift a FheString that was reversed and has on empty characters at the beginning
    /// It should not have empty characters at the and not anywhere in the middle.
    /// This is faster than ServerKey::left_shift_field and ServerKey::make_reusable
    fn left_shift_reverse(&self, fhe_string: &FheString) -> FheString{
        
        assert!(fhe_string.len()>0 && fhe_string.is_encrypted() && fhe_string.is_padded() && !fhe_string.is_reusable(),
            "FheString must be non empty, encrypted, padded, and not reusable");

        // we will shift the fhe_chars so the empty characters at the beginning go at the end and the FheString becomes reusable

        let len = fhe_string.len();
        let n_blocks = ServerKey::compute_blocks_for_len(len as u64);
        let true_len = self.len(fhe_string);
        let len_encrypted = self.key.create_trivial_radix(len as u64, n_blocks);
        let len_minus_true_len = self.key.sub_parallelized(&len_encrypted, &true_len);

        let index_is_len_minus_true_len: Vec<RadixCiphertext> = (0..len).into_par_iter().map(
            |index| self.key.scalar_eq_parallelized(&len_minus_true_len, index as u64)
        ).collect();

        // now left shift the fhe_string with the vector index_is_len_minus_true_len and tell it is reusable
        self.left_shift(fhe_string, &index_is_len_minus_true_len, true)
    }

    /// Left shift a FheString that has empty characters at the beginning or at the end only, and not anywhere in the middle.
    fn left_shift_field(&self, fhe_string: &FheString) -> FheString{
        
        assert!(fhe_string.len()>0 && fhe_string.is_encrypted() && fhe_string.is_padded() && !fhe_string.is_reusable(),
            "FheString must be non empty, encrypted, padded, and not reusable");

        // we will shift the fhe_chars so the empty characters at the beginning go at the end and the FheString becomes reusable

        // first, compute where the characters are not empty
        let mut first_non_zero: Vec<RadixCiphertext> = (0..fhe_string.len()).into_par_iter().map(
            |index| self.key.scalar_ne_parallelized(fhe_string.fhe_chars()[index].unwrap(), 0 as u64)
        ).collect();

        // then, keep only to one the first non zero character
        // this is iterative, it cannot be parallelized
        let mut first_one_seen = self.make_trivial_bool(false);
        for index in 0..fhe_string.len(){
            self.key.bitand_assign_parallelized(&mut first_non_zero[index], &self.not(&first_one_seen));
            self.key.bitor_assign_parallelized(&mut first_one_seen, &first_non_zero[index]);
        }

        // now left shift the fhe_string with the vector first_non_zero and tell it is reusable
        self.left_shift(fhe_string, &first_non_zero, true)
    } 
    
    /// Split a FheString into sub FheString given fields in cum_sum vector 
    fn split_result(&self,
        fhe_string: &FheString,
        pattern_is_padded: bool,
        pattern_len: usize,
        cum_sum: &Vec<RadixCiphertext>,
        stepped_range: Vec<usize>
        )
    -> Vec::<FheString> {
        // compute the minimal true length of the pattern to prevent computing unecessary things:
        let min_len_pattern = if pattern_is_padded{
            1
        }else{
            pattern_len
        };
        let step = if stepped_range.len() > 1 {
            stepped_range[1]
        }else{
            1
        };
        stepped_range.into_par_iter().map(
            |index_split|{

                // compute where the cum sum is not equal to index_split
                let mut cum_sum_ne_index: Vec<RadixCiphertext> = (0..cum_sum.len()).into_par_iter().map(
                    |index| {
                        if index >= (index_split/step)*min_len_pattern { // prevent computing if not necessary
                            let mut res = self.key.scalar_ne_parallelized(&cum_sum[index], index_split as u64);
                            let len = res.blocks().len()-1;
                            self.key.trim_radix_blocks_msb_assign(&mut res, len);
                            res
                        }else{
                            self.make_trivial_bool(false)
                        }
                    }
                ).collect();

                // match the size of cum_sum_ne_index with that of fhe_string
                if fhe_string.len() > cum_sum_ne_index.len(){
                    // use clones of the last value
                    let last_val_cum_sum_ne_index = cum_sum_ne_index[cum_sum_ne_index.len()-1].clone();
    
                    cum_sum_ne_index.extend(
                        std::iter::repeat(last_val_cum_sum_ne_index).take(fhe_string.len()-cum_sum_ne_index.len()
                        ).collect::<Vec<RadixCiphertext>>()
                    );
                }else{
                    // troncate the cum_sum_ne_index
                    cum_sum_ne_index.truncate(fhe_string.len())
                }

                // now return a FheString (padded, not reusable except for first index)
                // with empty characters where cum_sum_ne_index is true
                // also, take the index_split first indices of the string away because we know for sure they are empty
                let mut index_start = (index_split/step)*min_len_pattern;
                if index_start > fhe_string.len(){
                    index_start = fhe_string.len();
                }
                FheString::from_encrypted(
                    self.set_zero_where_indices(&fhe_string, &cum_sum_ne_index, index_start, fhe_string.len()),
                    true,
                    index_split==0 || (fhe_string.len()-index_start)==0
                )
            }
        ).collect()
    }


	/// General function for splitting a string into substrings in FHE
    /// `patterns` an array of patterns, if the array has size > 1, the patterns must be non padded single characters
    /// `splitn` whether to do split n or regular split
    /// `n_times` only for splitn. The number of seperations (different from self.splitn where n is the number of split results)
    /// `inclusive` wether we include pattern or not
    /// `terminator` wether we exclude the last pattern if ends the fhe_string
    /// `rsplit_terminator` wether to make a correction for the rsplit_terminator empty padded pattern scenario
    /// Rerturns :
    /// - the vector of split strings
    /// - the true number of fields of the result
    /// - wether we found the pattern
    /// - wether we the pattern is empty (this is used in replace)
    /// The true number of fields may be smaller than the total length of the return vector which is the number of fields
    /// required for the worst case scenario.
    // TODO : algorithm can be slightly improved if the pattern is not padded and with length 1
    // because we don't need pattern_ended anymore
	fn split_general(
        &self,
        fhe_string: &FheString,
        patterns: &[&FheString],
        splitn: bool,
        n_times: usize,
        inclusive:bool,
        terminator:bool,
        ascii_whitespace: bool,
        rsplit_terminator: bool,
    ) -> (Vec<FheString>, RadixCiphertext, RadixCiphertext, RadixCiphertext){

        // ######## CHECKING PARAMETERS ########

        let (pattern_is_encrypted, pattern_is_padded, pattern_len) = if ascii_whitespace{
            assert!(patterns.len()==0, "ascii_whitespace is true means patterns must be empty");
            (false, false, 1)
        }else{
            let pattern_is_encrypted_ = patterns[0].is_encrypted();

    		// make sure the patterns are correct:
            match patterns.len(){
                0 => panic!("No pattern provided"), // should have paniqued above if this is the case
                1 => ServerKey::assert_is_reusable(patterns[0], &"split_general"),
                _ => patterns.iter().for_each( |pattern| {
                    // make sure patterns are non padded single characters
                    assert!(pattern.len()==1 && !pattern.is_padded(), "mulitple patterns must be single characters and non padded");
                    assert!(pattern.is_encrypted()==pattern_is_encrypted_, "mulitple patterns must be all enrypted or all clear");
                })
            }

            (pattern_is_encrypted_, patterns[0].is_padded(), patterns[0].len())
        };

        // make sure we don't call splitn and inclusive together
        assert!( (splitn as u8 + inclusive as u8 + terminator as u8 + ascii_whitespace as u8) <= 1,
            "splitn, inclusive, terminator and ascii_whitespace are mutually exclusive");

        // ######## TRIVIAL RESULT ########

        if fhe_string.len()==0 {
            if ascii_whitespace {
                return (Vec::<FheString>::new(), 
                    self.key.create_trivial_zero_radix(1),
                    self.make_trivial_bool(false),
                    self.make_trivial_bool(true));
            }else{
                let mut res = Vec::<FheString>::new();
                if !inclusive && !terminator && !rsplit_terminator && !ascii_whitespace {
                    res.push(fhe_string.clone());
                }
                let mut number_of_fields = self.key.create_trivial_radix(res.len() as u64,1);
                // if there are several patterns, they cannot be empty, so checking one is sufficient
                let is_pattern_empty = self.is_empty(patterns[0]);
                self.key.add_assign_parallelized(&mut number_of_fields, &is_pattern_empty);
                res.push(fhe_string.clone());
                return (res,
                        number_of_fields,
                        is_pattern_empty,
                        self.make_trivial_bool(true));
            }      
        }

        if !pattern_is_padded && pattern_len > fhe_string.len() {
        	// if the pattern is not padded and is strictly longer than the string,
            // the pattern cannot be included and the result is trivial
        	let mut split_string = Vec::<FheString>::new();
            if !fhe_string.is_encrypted() && pattern_is_encrypted{
                split_string.push(fhe_string.trivial_encrypt(&self.key, 0));
            }else{
                split_string.push(fhe_string.clone());
            }
            let n_blocks = ServerKey::compute_blocks_for_len( split_string.len() as u64);
        	return (split_string,
                    self.key.create_trivial_radix(1u64, 1),
                    self.make_trivial_bool(false),
                    self.make_trivial_bool(false));
        }

        // ######## CLEAR INPUTS ########

        if !fhe_string.is_encrypted() && !pattern_is_encrypted {

            let (split_vec_clear, found) = if ascii_whitespace {
                let vec = fhe_string.to_string().split_ascii_whitespace().map(|s| s.to_string()).collect();
                (vec, fhe_string.to_string().contains(&[' ', '\t', '\n']))
            }else if patterns.len()==1 {
                let pattern_string = patterns[0].to_string();
                let vec: Vec<String> = if splitn {
                    fhe_string.to_string().splitn(n_times+1, &pattern_string).map(|s| s.to_string()).collect()
                }else if inclusive{
                    fhe_string.to_string().split_inclusive(&pattern_string).map(|s| s.to_string()).collect()
                }else if terminator{
                    fhe_string.to_string().split_terminator(&pattern_string).map(|s| s.to_string()).collect()
                }else{
                    fhe_string.to_string().split(&pattern_string).map(|s| s.to_string()).collect()
                };
                (vec, fhe_string.to_string().contains(&patterns[0].to_string()))
            }else{
                let patterns_chars: Vec<char> = patterns.iter().map(
                    |pattern| {
                        match pattern.to_string().chars().next(){
                            Some(char_) => char_,
                            None => panic!("should be a char")
                        }
                    }).collect();
                let vec: Vec<String> = if splitn {
                    fhe_string.to_string().splitn(n_times+1, &patterns_chars[0..patterns_chars.len()]).map(|s| s.to_string()).collect()
                }else if inclusive{
                    fhe_string.to_string().split_inclusive(&patterns_chars[0..patterns_chars.len()]).map(|s| s.to_string()).collect()
                }else if terminator{
                    fhe_string.to_string().split_terminator(&patterns_chars[0..patterns_chars.len()]).map(|s| s.to_string()).collect()
                }else{
                    fhe_string.to_string().split(&patterns_chars[0..patterns_chars.len()]).map(|s| s.to_string()).collect()
                };
                (vec, fhe_string.to_string().contains(&patterns_chars[0..patterns_chars.len()]))            
            };
            let mut split_vec: Vec::<FheString> = split_vec_clear.iter().map(|s| FheString::from_string(s) ).collect();
            if rsplit_terminator{
                split_vec.remove(0);
            }
            let n_blocks = ServerKey::compute_blocks_for_len( split_vec.len() as u64);
            let number_of_fields = self.key.create_trivial_radix(split_vec.len() as u64, n_blocks);
            return (split_vec,
                    number_of_fields,
                    self.make_trivial_bool(found),
                    self.make_trivial_bool(pattern_len==0));
        }

        // ######## DEAL WITH THE CASE WHERE THE PATTERN IS EMPTY AND NON PADDED ########

        // if the pattern is the empty string "" with or without padding, we need to create a special result for it.  
        // We need to create a sub-string for every character of fhe_string with empty sub-string at the beginning and end

        let mut results_from_empty: Vec::<FheString> = if ascii_whitespace {
            Vec::<FheString>::new() // unused
        // }else if splitn {
        //     let mut results_from_empty_ = Vec::<FheString>::with_capacity(cmp::max(fhe_string.len()+2usize,n_times));
        //     results_from_empty_.push( FheString::empty_encrypted() );
        //     for i in 0..cmp::min(fhe_string.len(), cmp::max(n_times-1, 0)){
        //         if fhe_string.is_encrypted(){
        //             let mut vec = Vec::<RadixCiphertext>::with_capacity(1);
        //             vec.push(fhe_string.fhe_chars()[i].unwrap().clone());
        //             results_from_empty_.push(FheString::from_encrypted(vec, true, true));
        //         }else{
        //             results_from_empty_.push(
        //                 FheString::from_string(
        //                     &fhe_string.chars()[i].to_string()
        //                 ).trivial_encrypt(&self.key,0)
        //             );
        //         }
        //     }
        //     if n_times > 0 && n_times < fhe_string.len(){
        //         if fhe_string.is_encrypted(){
        //             results_from_empty_.push(fhe_string.sub_string(n_times-1, fhe_string.len()-1))
        //         }else{
        //             results_from_empty_.push(
        //                 fhe_string.sub_string(n_times-1, fhe_string.len()-1).trivial_encrypt(&self.key, 0)
        //             )
        //         }
        //     }
        //     results_from_empty_        
        }else{
            let mut results_from_empty_ = Vec::<FheString>::with_capacity(fhe_string.len()+2);
            if !rsplit_terminator{
                results_from_empty_.push( FheString::empty_encrypted() );
            }
            for i in 0..fhe_string.len(){
                if fhe_string.is_encrypted(){
                    let mut vec = Vec::<RadixCiphertext>::with_capacity(1);
                    vec.push(fhe_string.fhe_chars()[i].unwrap().clone());
                    results_from_empty_.push(FheString::from_encrypted(vec, true, true));
                }else{
                    results_from_empty_.push(
                        FheString::from_string(
                            &fhe_string.chars()[i].to_string()
                        ).trivial_encrypt(&self.key,0)
                    );
                }
            }
            results_from_empty_
        };
        if !terminator && !inclusive && !(splitn && n_times < fhe_string.len()){
            results_from_empty.push(FheString::empty_encrypted());
        }
        let n_blocks_len_empty = ServerKey::compute_blocks_for_len( results_from_empty.len() as u64);
        let mut encrypted_len_empty = self.key.create_trivial_radix(results_from_empty.len() as u64, n_blocks_len_empty);


        // first, the special case where pattern is the empty string "" with no padding
        if pattern_len == 0 {
            // the string might be empty and padded, so we might need some corrections
            let mut number_of_fields_if_string_empty = if terminator || inclusive || (splitn && n_times==0) || rsplit_terminator {
                self.key.create_trivial_radix(1u8, 1)            
            }else{
                self.key.create_trivial_radix(2u8, 1)
            };

            let is_string_empty = self.is_empty(fhe_string);

            encrypted_len_empty = self.key.if_then_else_parallelized(
                &is_string_empty,
                &number_of_fields_if_string_empty,
                &encrypted_len_empty
            );            
            return (results_from_empty, encrypted_len_empty, self.make_trivial_bool(true), self.make_trivial_bool(true));
        }        


        // ######## LOOK FOR THE PATTERNS IN FHE_STRING ########

        // let us first get a vector telling for each index wether pattern is contained at this index:
        let mut contains_at_index_vec = if ascii_whitespace{
            self.is_whitespace(fhe_string)
        }else if patterns.len()==1{
            self.contains_at_index_vec(fhe_string, patterns[0])
        }else if patterns.len()==2{
            let vec_0 = self.contains_at_index_vec(fhe_string, patterns[0]);
            let vec_1 = self.contains_at_index_vec(fhe_string, patterns[1]);

            (0..vec_0.len()).into_par_iter().map(
                |index| self.key.bitor_parallelized(&vec_0[index], &vec_1[index])
            ).collect()
        }else{
            let all_vecs: Vec<Vec<RadixCiphertext>> = patterns.iter().map( 
                    |pattern| self.contains_at_index_vec(fhe_string, pattern)
                ).collect();
            (0..all_vecs.len()).into_par_iter().map(
                |index|{
                    let vec = (0..patterns.len()).into_iter().map(|i| all_vecs[i][index].clone()).collect::<Vec<RadixCiphertext>>();
                    vec.into_par_iter().reduce(
                        || self.make_trivial_bool(false),
                        |acc: RadixCiphertext, ele: RadixCiphertext| {
                        self.key.bitor_parallelized(&acc, &ele)
                    })
            }).collect::<Vec<RadixCiphertext>>()
        };

        // extend contains_at_index_vec with to match the size of fhe_string
        if !ascii_whitespace && fhe_string.len()-contains_at_index_vec.len() > 0 {
            let zero_cst = self.make_trivial_bool(false);
            let mut padding_vec = vec![zero_cst; fhe_string.len()-contains_at_index_vec.len()];
            contains_at_index_vec.append(&mut padding_vec);
        }
        // and add one more 0 value, needed for some special cases in the following algorithm
        contains_at_index_vec.push(self.make_trivial_bool(false));

        let len = contains_at_index_vec.len();

        // ######## MARKING THE FIELDS WITH A UNIQUE INDEX ########

        // We first need to process contains_at_index_vec so as to take note of delimitations between
        // fields of split sub-strings and occurences of the pattern.
        // We compute a cumulated sum vector that will record a different index value for each new field.
        // Split sub-strings will get odd values, and pattern occurences will get even values.
        // When a pattern immediately succeeds to another pattern, the value is increased by 2
        // For instance:
        //  "abcdefg".split("cd") => "001000-" => "0011222"
        //  "abababa".split("ba") => "010101-" => "0113355"

        let n_blocks = ServerKey::compute_blocks_for_len( cmp::max(len,pattern_len) as u64);
        
        let mut encrypted_pattern_length = if ascii_whitespace{
            self.key.create_trivial_radix(1,1)
        }else{
            self.len(patterns[0])
        };
        if encrypted_pattern_length.blocks().len() < n_blocks {
            let diff_blocks = n_blocks-encrypted_pattern_length.blocks().len();
            self.key.extend_radix_with_trivial_zero_blocks_msb_assign(
                &mut encrypted_pattern_length,
                diff_blocks
            );
        }
        let mut encrypted_string_length = self.len(fhe_string);

        let mut pattern_start_index = self.key.create_trivial_zero_radix(n_blocks);
        let mut cum_sum = Vec::<RadixCiphertext>::with_capacity(len); // cumulated sum of starting ones
        let mut first_one_seen = self.make_trivial_bool(false); // wether we encountered the first one
        let mut pattern_start_index_plus_pattern_length = self.make_trivial_bool(false);

        let encrypted_2n_times = self.key.create_trivial_radix((2*n_times) as u64, n_blocks);

        // this is iterative, it cannot be parallelized
        for index in 0..len{

            // if ascii_whitespace, things are easier
            if ascii_whitespace {
                if index==0 {
                    // for the first index, we don't need to sum up
                    cum_sum.push(self.key.extend_radix_with_trivial_zero_blocks_msb(&contains_at_index_vec[index], n_blocks-1));
                }else{       
                    // for other indices, increase cum_sum when we have either a 1 with a 0 before, or a 0 with a one before
                    // and if we are not above padding
                    if fhe_string.is_padded(){
                        let is_not_padding = self.key.scalar_gt_parallelized(&encrypted_string_length, index as u64);
                        let mut sum = self.key.bitxor_parallelized(&contains_at_index_vec[index], &contains_at_index_vec[index-1]);
                        self.key.bitand_assign_parallelized(&mut sum, &is_not_padding);
                        self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut sum, n_blocks-1);
                        cum_sum.push(self.key.add_parallelized(&cum_sum[index-1], &sum));                        
                    }else{
                        let mut sum = self.key.bitxor_parallelized(&contains_at_index_vec[index], &contains_at_index_vec[index-1]);
                        self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut sum, n_blocks-1);
                        cum_sum.push(self.key.add_parallelized(&cum_sum[index-1], &sum));
                    }
                }
            }else{

                // compute wether it is the first one
                // and
                // check the pattern ended and whether it just ended
                // This is required to prevent the pattern overlapping problems
                // for instance "ababababababab".split("abab") will have contains_at_index_vec like "0101010101.."
                // with the pattern overlapping itself

                let (is_first_one, pattern_start_index_plus_pattern_length_) = rayon::join(
                    || self.key.bitand_parallelized(&contains_at_index_vec[index], &self.not(&first_one_seen)),
                    || self.key.add_parallelized(&pattern_start_index, &encrypted_pattern_length)
                );

                pattern_start_index_plus_pattern_length = pattern_start_index_plus_pattern_length_; // keep value outside scope

                let (mut pattern_just_ended, mut pattern_ended) = rayon::join(
                    || self.key.scalar_eq_parallelized(&pattern_start_index_plus_pattern_length, index as u64),
                    || self.key.scalar_le_parallelized(&pattern_start_index_plus_pattern_length, index as u64)
                );

                // these two values only make sense if a pattern has started already
                rayon::join(
                    || self.key.bitand_assign_parallelized(&mut pattern_just_ended, &first_one_seen),
                    || self.key.bitand_assign_parallelized(&mut pattern_ended, &first_one_seen)
                );

                // udpate pattern_start_index
                // a new pattern starts if we have a first one or a one with pattern_ended
                let one_and_pattern_ended = self.key.bitand_parallelized(&contains_at_index_vec[index], &pattern_ended);
                let pattern_starts = self.key.bitor_parallelized(&is_first_one, &one_and_pattern_ended);
                let encrypted_index = self.key.create_trivial_radix(index as u64, n_blocks);
                pattern_start_index = self.key.if_then_else_parallelized(&pattern_starts, &encrypted_index, &pattern_start_index);

                // compute the cumulated sum value to separate fields
                // (1) The cumulated sum is increased of 1 if a new (non overlapping) pattern starts (if not inclusive)
                // (2) The cumulated sum is also increased by 1 if an occurence of the pattern just ended
                // whether it is followed by another occurence of the pattern (with thus an empty split string) or
                // a non empty split string
                if index==0 {
                    // for the first index, we don't need to sum up
                    let sum = if inclusive{
                        self.key.create_trivial_zero_radix(n_blocks)
                    }else{
                        self.key.extend_radix_with_trivial_zero_blocks_msb(&pattern_starts, n_blocks-1)
                    };
                    cum_sum.push(sum);
                }else{                    
                    // add up the previous value of cumulated sum with (1) pattern_starts (modified)                
                    let pattern_starts_extended = self.key.extend_radix_with_trivial_zero_blocks_msb(&pattern_starts, n_blocks-1);                    
                    self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut pattern_just_ended, n_blocks-1);
                    let mut sum = if inclusive{
                        cum_sum[index-1].clone()
                    }else{
                        self.key.add_parallelized(&cum_sum[index-1], &pattern_starts_extended)
                    };
                    // also (2) add pattern_just_ended                   
                    self.key.add_assign_parallelized(&mut sum, &pattern_just_ended);

                    if splitn {
                        // in this case, we want to block the sum to a maximum value of 2*n_times
                        let is_gt_n = self.key.scalar_gt_parallelized(&sum, 2*n_times as u64);
                        sum = self.key.if_then_else_parallelized(&is_gt_n, &encrypted_2n_times, &sum);
                    }
                    cum_sum.push(sum);
                }
            }

            // update first_one_seen for next iteration
            self.key.bitor_assign_parallelized(&mut first_one_seen, &contains_at_index_vec[index]);
        }

        // if ascii_whitespace, if the first character is a whitespace, we need to subtract 2 from cum_sum[index]
        // for all values that are >= 2 in order to prevent having an empty substring at start
        if ascii_whitespace{
            let sub_2_if_first_is_whitespace = self.key.if_then_else_parallelized(
                    &contains_at_index_vec[0],
                    &self.key.create_trivial_radix(2u8, n_blocks),
                    &self.key.create_trivial_zero_radix(n_blocks)
                );
            
            cum_sum = cum_sum.into_par_iter().map(
                |ele|{
                    let (is_ge_2, value_minus_2) =  rayon::join(
                        || self.key.scalar_ge_parallelized(&ele, 2u64),
                        || self.key.sub_parallelized(&ele, &sub_2_if_first_is_whitespace)
                    );
                    self.key.if_then_else_parallelized(&is_ge_2, &value_minus_2, &ele)
                }
            ).collect();
        }      

        // ######## SPLITTING FIELDS INTO SUB STRINGS ########

        // We will then keep only fields with even values which corresponds to split strings
        // and get rid of pattern occurences (if inclusive, keep them all)
        let mut len_split =0;

        if splitn {
            // in this case we just need n_times+1 results at worse
            len_split = 2*(n_times+1);
        }else if inclusive{
            len_split = if !pattern_is_padded {
                fhe_string.len().div_ceil(pattern_len)
            }else{
                fhe_string.len() //pattern true len could be 1
            };
        }else{
            len_split = if !pattern_is_padded {
                // If the pattern is not padded, the size of the return vector needs to
                // be 1+2*int( fhe_string.len()/pattern_len ) for the worst case scenario
                1+2*fhe_string.len()/pattern_len
            }else{
                // If the pattern is padded, we have to assume that it could be of any true length, even length 1
                // So the return vector should have a big size of 2*fhe_string.len() 
                2*fhe_string.len()
            };
            if terminator{
                len_split -= 1; // need one less at the end in the worse case scenario
            }          
        }
            
        // only take every two indices to skip the pattern, or every 1 if inclusive is true
        let stepped_range: Vec<usize> = (0..len_split).step_by(2-(inclusive as usize)).collect();

        // compute the number of fields that were found, which is often smaller than the size of the return vector
        // only in the worst case scenario they will be equal
        let mut number_of_fields = if inclusive {
            self.key.scalar_add_parallelized(&cum_sum[cum_sum.len()-1], 1u8)
        }else{
            let last_val_plus_two = self.key.scalar_add_parallelized(&cum_sum[cum_sum.len()-1], 2u8);
            self.key.div_parallelized(
                &last_val_plus_two,
                &self.key.create_trivial_radix(2u64, last_val_plus_two.blocks().len())
            )
        };

        // it terminator is true and we have an ending pattern, decrease number_of_fields by one
        if terminator{
            // the pattern ends the string if: pattern_start_index + len(pattern) == len(fhe_string)
            self.extend_equally(&mut pattern_start_index_plus_pattern_length, &mut encrypted_string_length);
            let mut pattern_ends_string = self.key.eq_parallelized(
                &pattern_start_index_plus_pattern_length,
                &encrypted_string_length
            );
            self.extend_equally(&mut number_of_fields, &mut pattern_ends_string);
            self.key.sub_assign_parallelized(&mut number_of_fields, &pattern_ends_string);
        }

        let split_results = if fhe_string.is_encrypted(){
            self.split_result(fhe_string, pattern_is_padded, pattern_len, &cum_sum, stepped_range)
        }else{
            // trivially encrypt fhe_string if it is clear before splitting it
            let encrypted = fhe_string.trivial_encrypt(&self.key, 0);
            self.split_result(&encrypted, pattern_is_padded, pattern_len, &cum_sum, stepped_range)
        };

        // If non empty and non padded pattern
        if pattern_len>0 && !pattern_is_padded {
            // the string might be empty and padded, so we might need some corrections
            let mut number_of_fields_if_string_empty = if terminator || inclusive || (splitn && n_times==0) || rsplit_terminator {
                self.key.create_trivial_radix(1u8, 1)            
            }else if ascii_whitespace{
                self.key.create_trivial_radix(0u8, 1)
            }else{
                self.key.create_trivial_radix(2u8, 1)
            };

            let is_string_empty = self.is_empty(fhe_string);

            number_of_fields = self.key.if_then_else_parallelized(
                &is_string_empty,
                &number_of_fields_if_string_empty,
                &number_of_fields
            );                
            return (split_results, number_of_fields, first_one_seen, self.make_trivial_bool(false));
        }

        // ######## DEAL WITH CASE WHERE STRING AND/OR PATTERN MIGHT BE EMPTY AND PADDED ########

        // the special case where pattern is the empty string "" with padding has to be
        // mixed with the other results because we don't know if pattern is empty or not in this case
        let is_pattern_empty = self.key.scalar_eq_parallelized(&encrypted_pattern_length, 0u8);

        let empty_fhe_string = FheString::empty_encrypted();
        let final_results = (0..cmp::max(split_results.len(),results_from_empty.len())).into_par_iter().map(
            |index|{
                if index >= split_results.len(){
                    self.if_then_else_fhe_string(&is_pattern_empty, &results_from_empty[index], &empty_fhe_string)
                }else if index >= results_from_empty.len(){
                    self.if_then_else_fhe_string(&is_pattern_empty, &empty_fhe_string, &split_results[index])
                }else{
                    self.if_then_else_fhe_string(&is_pattern_empty, &results_from_empty[index], &split_results[index])
                }
        }).collect();

        // update number_of_fields if the pattern is empty and / or the string is empty

        let (mut is_string_empty, mut not_is_pattern_empty) = rayon::join(
            || self.key.scalar_eq_parallelized(&encrypted_string_length, 0u8),
            || self.not(&is_pattern_empty)
        );

        self.extend_equally(&mut encrypted_len_empty, &mut is_string_empty);
        self.key.sub_assign_parallelized(&mut encrypted_len_empty, &is_string_empty);

        (number_of_fields, _) = rayon::join(
            ||self.key.if_then_else_parallelized(
                &is_pattern_empty,
                &encrypted_len_empty,
                &number_of_fields
            ),
            || self.key.bitor_assign_parallelized(&mut first_one_seen, &is_pattern_empty)
        );

        let mut number_of_fields_if_string_empty = if terminator || inclusive || (splitn && n_times==0) || ascii_whitespace || rsplit_terminator {
            self.key.create_trivial_radix(1u8, 1)
        }else{
            self.key.create_trivial_radix(2u8, 1)
        };
        self.extend_equally(&mut number_of_fields_if_string_empty, &mut not_is_pattern_empty);
        self.key.sub_assign_parallelized(&mut number_of_fields_if_string_empty, &not_is_pattern_empty);

        self.extend_equally(&mut number_of_fields_if_string_empty, &mut number_of_fields);
        number_of_fields = self.key.if_then_else_parallelized(
            &is_string_empty,
            &number_of_fields_if_string_empty,
            &number_of_fields
        );

        (final_results, number_of_fields, first_one_seen, is_pattern_empty)
	}

    /// Reverses inputs for the rsplit functions
    fn reverse_inputs(&self, fhe_string: &FheString, pattern: &FheString) -> (FheString, FheString){

        // first, reverse the inputs
        let mut reverse_fhe_string = fhe_string.clone();
        let mut reverse_pattern = pattern.clone();
        reverse_fhe_string.reverse();
        reverse_pattern.reverse();

        // use left_shift_reverse on pattern if it is encrypted abd padded
        if reverse_pattern.is_padded(){
            reverse_pattern = self.left_shift_reverse(&reverse_pattern);
        }

        (reverse_fhe_string, reverse_pattern)
    }

    /// Makes results of a split reusable
    fn make_split_reusable(&self, split_result: (Vec<FheString>, RadixCiphertext))-> (Vec<FheString>, RadixCiphertext){
        let (mut split_string, number_of_fields) = split_result;
        if split_string.len()<=1{
            return (split_string, number_of_fields);
        }
        let mut split_string_reusable = (1..split_string.len()).into_par_iter().map(
            |index|{
                match split_string[index].is_reusable(){
                    true => split_string[index].clone(),
                    false => self.left_shift_field(&split_string[index])
                }
            }
        ).collect();
        split_string.truncate(1); // the first element is already reusable
        split_string.append(&mut split_string_reusable);
        (split_string, number_of_fields)        
    }    

    /// Split implementation for FheStrings that does not check if the fhe_string is reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    fn unchecked_split(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        ServerKey::assert_is_reusable(pattern, &"unchecked_split");  
        let (split_res, number_of_fields, _, _) = self.split_general(fhe_string, &[pattern], false, 0, false, false, false, false);
        (split_res, number_of_fields)
    }

    /// Split implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::split_reusable
    pub fn split(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split");  
        self.unchecked_split(fhe_string, pattern)
    }

    /// Additional split implementation for FheStrings that returns wether the pattern is empty
    pub (crate) fn split_pattern_empty(&self, fhe_string: &FheString, pattern: &FheString)
        -> (Vec<FheString>, RadixCiphertext, RadixCiphertext)
    {
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_pattern_empty");  
        ServerKey::assert_is_reusable(pattern, &"split_pattern_empty");  
        let (split_res, number_of_fields, _, is_pattern_empty) = 
            self.split_general(fhe_string, &[pattern], false, 0, false, false, false, false);
        (split_res, number_of_fields, is_pattern_empty)
    }

    /// Split implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn split_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_reusable");
        self.make_split_reusable( self.split(fhe_string, pattern) )
    }    

    /// Rsplit a string into substrings around where the second string has been found
    /// Returns a Vec<FheString> with the matching fields along with the number of non empty fields
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::rsplit_reusable
    // Let's reuse cleverly our split function by applying it to reversed inputs, and reverse the results
    pub fn rsplit(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplit");
        ServerKey::assert_is_reusable(pattern, &"rsplit");

        // first, reverse the inputs
        let (reverse_fhe_string, reverse_pattern) = self.reverse_inputs(fhe_string, pattern);

        // compute the split on the reversed inputs
        let (mut reverse_split_string, number_of_fields) = self.unchecked_split(&reverse_fhe_string, &reverse_pattern);

        // reverse elements of the return vector
        reverse_split_string = reverse_split_string.iter().map( |fhe_str| {
            let mut reversed = fhe_str.clone();
            reversed.reverse();
            reversed
        }).collect();

        (reverse_split_string, number_of_fields)
    }

    /// Rsplit implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn rsplit_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplit_reusable");
        self.make_split_reusable( self.rsplit(fhe_string, pattern) )
    }        

    /// Split_inclusive implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::split_inclusive_reusable
    pub fn split_inclusive(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_inclusive");  
        ServerKey::assert_is_reusable(pattern, &"split_inclusive");  
        let (split_res, number_of_fields, _, _) = self.split_general(fhe_string, &[pattern], false, 0, true, false, false, false);
        (split_res, number_of_fields)
    }

    /// Split_inclusive implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn split_inclusive_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_inclusive_reusable");
        self.make_split_reusable( self.split_inclusive(fhe_string, pattern) )
    }      

    /// Split_terminator implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::split_terminator_reusable
    pub fn split_terminator(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_terminator");  
        ServerKey::assert_is_reusable(pattern, &"split_terminator");
        let (split_res, number_of_fields, _, _) = self.split_general(fhe_string, &[pattern], false, 0, false, true, false, false);
        (split_res, number_of_fields)
    }

    /// Split_terminator implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn split_terminator_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_terminator_reusable");
        self.make_split_reusable( self.split_terminator(fhe_string, pattern) )
    }       

    /// Rsplit_terminator implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::rsplit_terminator_reusable
    pub fn rsplit_terminator(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_terminator");  
        ServerKey::assert_is_reusable(pattern, &"split_terminator");

        if !fhe_string.is_encrypted() && !pattern.is_encrypted(){
            let split_clear: Vec<FheString> = 
                fhe_string.to_string().rsplit_terminator(&pattern.to_string()).map(
                    |s| FheString::from_string(&s.to_string())
                ).collect();
            let n_blocks = ServerKey::compute_blocks_for_len(split_clear.len() as u64);
            let number_of_fields =  self.key.create_trivial_radix(split_clear.len() as u64, n_blocks);
            return (split_clear, number_of_fields);
        }

        // first, strip the pattern suffix to the fhe_string if it ends it
        let (stripped_fhe_string, _) = self.strip_suffix(fhe_string, pattern); 
        
        // then, reverse the inputs
        let (reverse_fhe_string, reverse_pattern) = self.reverse_inputs(&stripped_fhe_string, pattern);

        // compute the split on the reversed inputs
        let (mut reverse_split_string, mut number_of_fields, _, _) = 
            self.split_general(&reverse_fhe_string, &[&reverse_pattern], false, 0, false, false, false, true);

        // reverse elements of the return vector
        reverse_split_string = reverse_split_string.iter().map( |fhe_str| {
            let mut reversed = fhe_str.clone();
            reversed.reverse();
            reversed
        }).collect();

        (reverse_split_string, number_of_fields)
    }

    /// Rsplit_terminator implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn rsplit_terminator_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplit_terminator_reusable");
        self.make_split_reusable( self.rsplit_terminator(fhe_string, pattern) )
    }     

    /// Split_ascii_whitespace implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::split_ascii_whitespace_reusable
    pub fn split_ascii_whitespace(&self, fhe_string: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the input is reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_ascii_whitespace");  
        let (split_res, number_of_fields, _, _) = self.split_general(fhe_string, &[], false, 0, false, false, true, false);
        (split_res, number_of_fields)
    }

    /// Split_ascii_whitespace implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn split_ascii_whitespace_reusable(&self, fhe_string: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_ascii_whitespace_reusable");
        self.make_split_reusable( self.split_ascii_whitespace(fhe_string) )
    }      

    /// Splitn implementation for FheStrings that does not check if the fhe_string is reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    fn unchecked_splitn(&self, n_times: usize, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        ServerKey::assert_is_reusable(pattern, &"unchecked_splitn");
        assert!(n_times>0, "n_times must be positive");
        let (split_res, number_of_fields, _, _) = self.split_general(fhe_string, &[pattern], true, n_times-1, false, false, false, false);
        (split_res, number_of_fields)
    }  

    /// Splitn implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::splitn_reusable
    pub fn splitn(&self, n_times: usize, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"splitn");

        if n_times == 0 {
            return (Vec::<FheString>::new(), self.key.create_trivial_zero_radix(1));
        }
        if n_times == 1 {
            let mut res = Vec::<FheString>::new();
            res.push(fhe_string.clone());
            return (res, self.key.create_trivial_radix(1u8, 1));
        }        

        self.unchecked_splitn(n_times, fhe_string, pattern)
    }

    /// Additional split implementation for FheStrings that returns wether the pattern is empty
    pub (crate) fn splitn_pattern_empty(&self, n_times: usize, fhe_string: &FheString, pattern: &FheString)
        -> (Vec<FheString>, RadixCiphertext, RadixCiphertext)
    {
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"splitn_pattern_empty");  
        ServerKey::assert_is_reusable(pattern, &"splitn_pattern_empty");
        assert!(n_times>0, "n_times must be positive");
        let (split_res, number_of_fields, _, is_pattern_empty) = 
            self.split_general(fhe_string, &[pattern], true, n_times-1, false, false, false, false);
        (split_res, number_of_fields, is_pattern_empty)
    }    

    /// Splitn implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn splitn_reusable(&self, n_times: usize, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"splitn_reusable");
        self.make_split_reusable( self.splitn(n_times, fhe_string, pattern) )
    }       

    /// Rsplitn implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::rsplitn_reusable
    pub fn rsplitn(&self, n_times: usize, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplitn");
        ServerKey::assert_is_reusable(pattern, &"rsplitn");

        if n_times == 0 {
            return (Vec::<FheString>::new(), self.key.create_trivial_zero_radix(1));
        }
        if n_times == 1 {
            let mut res = Vec::<FheString>::new();
            res.push(fhe_string.clone());
            return (res, self.key.create_trivial_radix(1u8, 1));
        }         

        // first, reverse the inputs
        let (reverse_fhe_string, reverse_pattern) = self.reverse_inputs(fhe_string, pattern);

        // compute the split on the reversed inputs
        let (mut reverse_split_string, number_of_fields) = self.unchecked_splitn(n_times, &reverse_fhe_string, &reverse_pattern);

        // reverse elements of the return vector
        reverse_split_string = reverse_split_string.iter().map( |fhe_str| {
            let mut reversed = fhe_str.clone();
            reversed.reverse();
            reversed
        }).collect();

        (reverse_split_string, number_of_fields)
    }  

    /// Rsplitn implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn rsplitn_reusable(&self, n_times: usize, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplitn_reusable");
        self.make_split_reusable( self.rsplitn(n_times, fhe_string, pattern) )
    }       

    /// Split_once implementation for FheStrings that does not check if the fhe_string is reusable
    /// Returns a Vec<FheString> with the result fields along with a boolean telling if the pattern was found
    fn unchecked_split_once(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(pattern, &"unchecked_split_once");
        let (split_string, _, found, _) = self.split_general(fhe_string, &[pattern], true, 1, false, false, false, false);
        (split_string, found)
    }  

    /// Split_once implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with a boolean telling if the pattern was found
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::split_once_reusable
    pub fn split_once(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_once");

        if !pattern.is_padded() && pattern.len() > fhe_string.len() {
            return (Vec::<FheString>::new(), self.make_trivial_bool(false));
        }

        if fhe_string.len()==0 {
            // different behavior than "".splitn(2, "..") in this case
            let mut res = Vec::<FheString>::new();
            res.push(fhe_string.clone());
            res.push(fhe_string.clone());            
            let is_empty_pattern = self.is_empty(pattern);
            return (res, is_empty_pattern);
        }

        self.unchecked_split_once(fhe_string, pattern)
    }  

    /// Split_once implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn split_once_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"split_once_reusable");
        self.make_split_reusable( self.split_once(fhe_string, pattern) )
    }      

    /// Rsplit_once implementation for FheStrings
    /// Returns a Vec<FheString> with the result fields along with a boolean telling if the pattern was found
    /// Warning: the results split strings are not reusable (except for the first one). See ServerKey::rsplit_once_reusable
    pub fn rsplit_once(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplit_once");
        ServerKey::assert_is_reusable(pattern, &"rsplit_once");

        if !pattern.is_padded() && pattern.len() > fhe_string.len() {
            return (Vec::<FheString>::new(), self.make_trivial_bool(false));
        }
        
        if fhe_string.len()==0 {
            // different behavior than "".splitn(2, "..") in this case
            let mut res = Vec::<FheString>::new();
            res.push(fhe_string.clone());
            res.push(fhe_string.clone());            
            let is_empty_pattern = self.is_empty(pattern);
            return (res, is_empty_pattern);
        }

        // first, reverse the inputs
        let (reverse_fhe_string, reverse_pattern) = self.reverse_inputs(fhe_string, pattern);

        // compute the split on the reversed inputs
        let (mut reverse_split_string, found) = self.unchecked_split_once(&reverse_fhe_string, &reverse_pattern);

        // reverse elements of the return vector
        reverse_split_string.iter_mut().for_each(|fhe_str| fhe_str.reverse());

        if reverse_split_string.len()>2{
            reverse_split_string.truncate(2);
        }

        // reverse vector itself for the particular case of rsplit_once (contrary to rsplit and rsplitn)        
        reverse_split_string.reverse();

        (reverse_split_string, found)
    }  

    /// Rsplit_once implementation for FheStrings that makes the results reusable
    /// Returns a Vec<FheString> with the result fields along with the number of non empty fields    
    pub fn rsplit_once_reusable(&self, fhe_string: &FheString, pattern: &FheString) -> (Vec<FheString>, RadixCiphertext){
        // make sure the inputs are both reusable:
        ServerKey::assert_is_reusable(fhe_string, &"rsplit_once_reusable");
        self.make_split_reusable( self.rsplit_once(fhe_string, pattern) )
    }      

}