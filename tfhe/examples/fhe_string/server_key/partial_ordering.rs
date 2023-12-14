//! ServerKey implementation of partial ordering functions to compare ciphertext::FheString objects

use tfhe::integer::ciphertext::RadixCiphertext;
use rayon::prelude::*;

use crate::ciphertext::FheString;

use super::ServerKey;

impl ServerKey{

	/// Computes wether a FheString is lower than another, in alphabetical order
	/// Warning: Requires reusable FheStrings
	///
	/// A FheString A is lower than a FheString B if and only if:
	/// there exist an index i such that: A[i] < B[i]  AND  for all k<i, A[k] <= B[k]
	///
	/// If sequence have different length, the shorter one is considered to have extra empty characters
	/// where the empty character is the lowest in alphabetical order
	pub fn lt(&self, fhe_string_a: &FheString, fhe_string_b: &FheString) -> RadixCiphertext{
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_a, &"lt");
        ServerKey::assert_is_reusable(fhe_string_b, &"lt");

		// prepare arrays if they have different size
		let len_a = fhe_string_a.len();
		let len_b = fhe_string_b.len();

		// special cases first
		if len_a == 0{
			// if A is empty, then it is lower than B except if B is empty
			return self.not( &self.is_empty(fhe_string_b) );
		}
		if len_b == 0{
			// if B is empty, then A can never be lt B
			return self.make_trivial_bool(false);
		}

		// now we know A and B both have non 0 length

		// crop the longest sequence to match the size of the shortest, and keep indices of the slice
		// this is almost the same as appending zeros to the shortest to match the longest
		// but it is quicker, provided we make proper verifications at the end of the function (*)

		let (start_a, end_a) = match len_b < len_a {
			true => (0, len_b),
			false => (0, len_a)
		};

		let (start_b, end_b) = match len_b > len_a {
			true => (0, len_a),
			false => (0, len_b)
		};


		let (is_a_lt_b, is_a_eq_b) = match (fhe_string_a.is_encrypted(), fhe_string_b.is_encrypted()){
			(false, false) => {
				// if the two strings are unencrypted, we end the function with a trivial result
				return self.make_trivial_bool( fhe_string_a.slice_to_string(start_a, end_a) < fhe_string_b.slice_to_string(start_b, end_b) );
			},
			(true, false) => {
				// if the first is encrypted and the other is clear
				// compute A[i] < B[i] and A[i] == B[i] in parallel
				rayon::join(
					|| self.parallelized_vec_2_bool_function(
						&fhe_string_a.fhe_chars()[start_a..end_a],
						&fhe_string_b.chars()[start_b..end_b],
						|(fhe_c, c)| self.key.scalar_lt_parallelized(fhe_c.unwrap(), (*c) as u8).into_radix(1, &self.key)
					),
					|| self.parallelized_vec_2_bool_function(
						&fhe_string_a.fhe_chars()[start_a..end_a],
						&fhe_string_b.chars()[start_b..end_b],
						|(fhe_c, c)| self.key.scalar_eq_parallelized(fhe_c.unwrap(), (*c) as u8).into_radix(1, &self.key)
					))
			},
			(false, true) => {
				// if the first is clear and the other is encrypted
				// compute A[i] < B[i] and A[i] == B[i] in parallel
				rayon::join(
					|| self.parallelized_vec_2_bool_function(					
						&fhe_string_b.fhe_chars()[start_b..end_b],
						&fhe_string_a.chars()[start_a..end_a],
						|(fhe_c, c)| self.key.scalar_gt_parallelized(fhe_c.unwrap(), (*c) as u8).into_radix(1, &self.key)
					),
					|| self.parallelized_vec_2_bool_function(
						&fhe_string_b.fhe_chars()[start_b..end_b],
						&fhe_string_a.chars()[start_a..end_a],
						|(fhe_c, c)| self.key.scalar_eq_parallelized(fhe_c.unwrap(), (*c) as u8).into_radix(1, &self.key)
					))
			},
			(true, true) => {
				// If both are encrypted
				// compute A[i] < B[i] and A[i] == B[i] in parallel
				rayon::join(
					|| self.parallelized_vec_2_bool_function(
						&fhe_string_a.fhe_chars()[start_a..end_a],
						&fhe_string_b.fhe_chars()[start_b..end_b],
						|(fhe_c_1, fhe_c_2)| self.key.lt_parallelized(fhe_c_1.unwrap(), fhe_c_2.unwrap()).into_radix(1, &self.key)
					),
					|| self.parallelized_vec_2_bool_function(
						&fhe_string_a.fhe_chars()[start_a..end_a],
						&fhe_string_b.fhe_chars()[start_b..end_b],
						|(fhe_c_1, fhe_c_2)| self.key.eq_parallelized(fhe_c_1.unwrap(), fhe_c_2.unwrap()).into_radix(1, &self.key)
					))
			}
		};

		// now let check if there exist an index i such that: "A[i] < B[i]  AND  for all k<i, A[k] == B[k]"
		/// and wether for all i, A[i] == B[i]

		// let's build a vector to record for each i wether "for all k<i, A[k] == B[k]"
		let mut all_k_before_eq = Vec::<RadixCiphertext>::with_capacity(is_a_lt_b.len());
		// we initialise it with a true value for index 0 because there is no k<0
		all_k_before_eq.push(self.make_trivial_bool(true));
		// this loop is sequential, it cannot be parallelized
		for i in 1..=is_a_lt_b.len(){
			all_k_before_eq.push( self.key.bitand_parallelized(&all_k_before_eq[i-1], &is_a_eq_b[i-1]) );
		}

		// now let's compute in parallel a vector to tell for each i wether A[i] < B[i] AND "for all k<i, A[k] == B[k]"
		let is_lt_and_all_k : Vec<RadixCiphertext> = (0..=is_a_lt_b.len()-1).into_par_iter().map( |index| {
			self.key.bitand_parallelized(&all_k_before_eq[index], &(is_a_lt_b[index]))
		}).collect();

		// now we just need to know if there exist any true value in is_lt_and_all_k
		let exists_i = self.any(is_lt_and_all_k);
		
		// exists_i contains the answer to A < B
		// we also need to return wether for all i, A[i] == B[i] which is stored in the last (unused) value of all_k_before_eq
		let all_equal = all_k_before_eq.pop().unwrap();
		
		// now modify the result in the case where both sub-strings are equal
		// recall at (*) that we may have cut one of the sequences to match the size of the other
		// and if both substrings happen to be equal, the result will depend on the content of the part that was cut out

		// if the lengths are identical or if A was cut (len_b < len_a), the result A < B is already in exists_i
		if len_a >= len_b {
			return exists_i;
		}

		// if B was cut, then either exists_i is true and A < B, either exists_i is false and in this case,
		// A < B only if all_equal is true and the cut part of B is non empty (non null)

		// return exists_i OR ( all_equal AND cut_B is non null )
		let cut_b_positive = self.not( &self.is_empty_indices(fhe_string_b, (len_a, len_b)) );
		let eq_and_pos = self.key.bitand_parallelized(&cut_b_positive, &all_equal);
		self.key.bitor_parallelized(&exists_i, &eq_and_pos)
	}

	/// Computes wether a FheString is lower or equal to another, in alphabetical order
	/// Warning: Requires reusable FheStrings	
	/// 
	/// The proposition "A <= B" is equivalent to "not (B < A)" (see self.__lt__)
	///
	/// If sequence have different length, the shorter one is considered to have extra empty characters
	/// where the empty character is the lowest in alphabetical order        
	pub fn le(&self, fhe_string_a: &FheString, fhe_string_b: &FheString) -> RadixCiphertext{
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_a, &"le");
        ServerKey::assert_is_reusable(fhe_string_b, &"le");

		let mut is_b_lt_a = self.lt(fhe_string_b, fhe_string_a);
		self.not(&mut is_b_lt_a)
	}

	///	Computes wether a FheString is greater than another, in alphabetical order
	/// Warning: Requires reusable FheStrings	
	///	
	///	The proposition "A > B" is the symetry of "B < A" (see self.__lt__)
	///	
	///	If sequence have different length, the shorter one is considered to have extra empty characters
	///	where the empty character is the lowest in alphabetical order    
	pub fn gt(&self, fhe_string_a: &FheString, fhe_string_b: &FheString) -> RadixCiphertext{
		// make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_a, &"gt");
        ServerKey::assert_is_reusable(fhe_string_b, &"gt");

		self.lt(fhe_string_b, fhe_string_a)
	}

	/// Computes wether a FheString is greater or equal to another, in alphabetical order
	/// Warning: Requires reusable FheStrings	
	///
	/// The proposition "A >= B" is equivalent to of "not (A < B)" (see lt_fhe_string)
	///
	/// If sequence have different length, the shorter one is considered to have extra empty characters
	/// where the empty character is the lowest in alphabetical order
	pub fn ge(&self, fhe_string_a: &FheString, fhe_string_b: &FheString) -> RadixCiphertext{
        // make sure the two FheStrings are reusable first:
        ServerKey::assert_is_reusable(fhe_string_a, &"ge");
        ServerKey::assert_is_reusable(fhe_string_b, &"ge");

		let mut is_a_lt_b = self.lt(fhe_string_a, fhe_string_b);
		self.not(&mut is_a_lt_b)
	}

}