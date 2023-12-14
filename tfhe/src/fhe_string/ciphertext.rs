//! The ciphertext module implements wrappers for Strings made of ASCII characters

use std::cmp::max;

use tfhe::integer::client_key::RadixClientKey;
use tfhe::integer::server_key::ServerKey;
use tfhe::integer::ciphertext::{RadixCiphertext, IntegerCiphertext};

use crate::NUMBER_OF_BLOCKS;


/// Assert that a character is ascii
fn assert_is_ascii(character: &char){
    assert!( character.is_ascii(),
        "{}", format!("This character is not ascii: {}", *character)
    );
}

/// Assert that a character is non null
fn assert_positive(character: &char){
    assert!( (*character as u8) > 0u8, 
        "Null characters are not allowed, they are reserved to padding");
}

/// A struct wrapping an 8-bits RadixCiphertext to encrypt a char
#[derive(Clone)]
pub struct FheAsciiChar{
    fhe_ascii_char: RadixCiphertext,
}

impl FheAsciiChar{

    /// Build directly from a RadixCiphertext
    /// Warning: this function must be used with precaution because the encrypted could be non ASCII
    fn from_encrypted(crt: RadixCiphertext) -> Self{
        // check that the character is 8 bits
        assert!(crt.blocks().len() == NUMBER_OF_BLOCKS, "Encrypted character should be 8 bits");
        Self {
            fhe_ascii_char: crt,
        }
    }

    /// Encrypts a char into a RadixCiphertext and wraps it into a FheAsciiChar
    /// It will first verify that the char is ASCII
    ///
    /// `character` the character to encrypt
    /// `client_key` the RadixClientKey used to encrypt
    /// Returns a FheAsciiChar wrapping the RadixCiphertext encrypting the character    
    fn encrypt(character: &char, client_key: &RadixClientKey) -> Self {        
        assert_is_ascii(character);
        Self {
            fhe_ascii_char: client_key.encrypt((*character) as u8),
        }
    }

    /// Encrypts trivially a char into a RadixCiphertext and wraps it into a FheAsciiChar
    /// It will first verify that the char is ASCII
    ///
    /// `character` the character to encrypt
    /// `server_key` the ServerKey used to encrypt
    /// Returns a FheAsciiChar wrapping the RadixCiphertext encrypting the character    
    fn trivial_encrypt(character: &char, server_key: &ServerKey) -> Self {        
        assert_is_ascii(character);
        Self {
            fhe_ascii_char: server_key.create_trivial_radix((*character) as u8, NUMBER_OF_BLOCKS),
        }
    }     

    /// Decrypts the wrapped RadixCiphertext into a char
    ///
    /// `client_key` the RadixClientKey used to decrypt
    /// Returns the decrypted RadixCiphertext as a char    
    fn decrypt(&self, client_key: &RadixClientKey) -> char {  
        let decrypted: u8 = client_key.decrypt(&self.fhe_ascii_char);
        let character = decrypted as char;
        assert_is_ascii(&character);
        character
    }   

    /// Unwrap the wrapped RadixCiphertext
    ///
    /// Returns the wrapped RadixCiphertext    
    pub fn unwrap(&self) -> &RadixCiphertext {        
        &self.fhe_ascii_char
    }

}


/// A struct wrapping a Vec of FheAsciiChar or a Vec<char> to store an encrypted or clear String of ASCII characters
#[derive(Clone)]
pub struct FheString{
    // chars and fhe_chars should never be filled together, either one of them is empty at all time
    chars: Vec<char>, // store chars when unencrypted
    fhe_chars: Vec<FheAsciiChar>, // store FheAsciiChars when encrypted
    // Wether the FheString is encrypted or clear
    is_encrypted: bool ,
    // Record wether there is \0 padding or not:
    // Being sure there is no padding leads to increased performances
    // If there is no padding but is_padded is True, the results are still valid, but slower
    // This can happen when we extract a substring out of a padded string and the substring happens
    // to be not padded, but we say it is just in case.
    is_padded: bool,
    // Record wether the FheString contains \0 characters somewhere else than at the end (which would be padding)
    // This can happen in output of some algorithms. It can be corrected but at a high computational cost
    // See _reusable functions
    is_reusable: bool,
}

impl FheString {

    fn assert_encrypted(&self, message: &str){
        assert!(
            self.is_encrypted,
            "{}", format!("Should not call {} on an clear FheString object", message)
        );
    }

    fn assert_clear(&self, message: &str){
        assert!(
            !self.is_encrypted,
             "{}", format!("Should not call {} on an encrypted FheString object", message)
        );
    }    

    /// Getter of private attribute is_encrypted which tells
    /// wether the FheString is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// Tell if the FheString is clear
    pub fn is_clear(&self) -> bool {
        !self.is_encrypted
    }    

    /// Getter of private attribute is_padded which tells
    /// wether the FheString may have padding or not
    pub fn is_padded(&self) -> bool {
        self.is_padded
    }    

    // Getter of private attribute is_reusable which tells
    // wether the FheString is reusable as an input to other algorithms or not
    pub fn is_reusable(&self) -> bool {
        self.is_reusable
    }    

    /// Build a clear FheString from a String
    /// This allows both to check the validity of the characters and the compatibility with encrypted FheStrings
    pub fn from_string(string: &String) -> FheString{
        // convert string to vec<char>
        let chars = string.chars().collect::<Vec<char>>();
        // check that values are positive and ascii
        chars.iter().for_each( |c| {
            assert_positive(&c);
            assert_is_ascii(&c);
        });
        Self{
            chars,
            fhe_chars: Vec::<FheAsciiChar>::new(),
            is_encrypted: false,
            is_padded: false,
            is_reusable: true,
        }
    }

    /// Build a clear FheString from a &str
    pub fn from_str(str: &str) -> FheString{
        FheString::from_string(&str.to_string())
    }    

    /// Build from a Vec<RadixCiphertext>, telling wether the string is reusable, i.e. wether it contains \0 null
    /// characters in the middle of the string (not just at the end).
    ///
    /// Warning: this function is pub(crate), it should not be used by the end user because
    /// there could be non ASCII on non positive characters
    /// Warning: the function takes ownership of the Vec<RadixCiphertext> to avoid cloning
    // TODO: make ct_vec mutable and empty it for cleaner use
    pub (crate) fn from_encrypted(ct_vec: Vec<RadixCiphertext>, is_padded: bool, is_reusable: bool) -> Self{
        Self {
            chars: Vec::<char>::new(),
            fhe_chars: ct_vec.into_iter().map(|ct| FheAsciiChar::from_encrypted(ct)).collect(),
            is_encrypted: true,
            is_padded,
            is_reusable,
        }
    }

    /// Build an empty encrypted FheString
    pub fn empty_encrypted() -> Self{
        Self {
            chars: Vec::<char>::new(),
            fhe_chars: Vec::<FheAsciiChar>::new(),
            is_encrypted: true,
            is_padded: false,
            is_reusable: true
        }
    }    

    /// Returns the visible length of the FheString, which is the number of its characters (padding included)
    /// Recall that the hidden length is different: it doesn't not include the padding
    pub fn len(&self) -> usize {
        max(self.chars.len(), self.fhe_chars.len())
    }

    /// Create a FheString that is a substring of the FheString
    /// `index_start` the first index
    /// `index_end` the last index (included)
    /// Returns a new FheString with values copied from the original
    pub fn sub_string(&self, index_start: usize, index_end: usize) -> FheString {

        let sub_vec_char = (|| {
            if self.is_encrypted{
                Vec::<char>::new()
            }else{
                self.chars[index_start..=index_end].to_vec()
            }
        })();

        let sub_vec_fhe_char = (|| {
            if self.is_encrypted{
                self.fhe_chars[index_start..=index_end].to_vec()
            }else{
                Vec::<FheAsciiChar>::new()
            }
        })();
        
        Self {
            chars: sub_vec_char,
            fhe_chars: sub_vec_fhe_char,
            // set true because we don't know (if it has no padding, it will work all the same but slower)
            is_padded: true,
            is_encrypted: self.is_encrypted,
            is_reusable: self.is_reusable,
        }
    }

    /// Encrypts a clear fhe_string into an encrypted one
    ///
    /// `client_key` a reference to a RadixClientKey used to encrypt
    /// `padding` the length of the null characters padding to append
    ///  to the string before encryption in order to hide its length
    /// Returns a new encrypted FheString    
    pub fn encrypt(&self, client_key: &RadixClientKey, padding: usize) -> Self {
        self.assert_clear("encrypt");
        // encrypt characters
        let mut fhe_chars = self.chars.iter()
            .map(|c| FheAsciiChar::encrypt(&c, client_key))
            .collect::<Vec<FheAsciiChar>>();

        // append padding null characters so as to hide its length if padding > 0
        if padding > 0{
            let zero_cst = 0u8 as char;
            let zero_cst_encrypted = FheAsciiChar::encrypt(&zero_cst, client_key);
            
            let mut padding_vec = vec![zero_cst_encrypted; padding];
            fhe_chars.append(&mut padding_vec);
        }

        Self {
            chars: Vec::<char>::new(),
            fhe_chars,
            is_encrypted: true,
            is_padded: padding > 0,            
            //is_padded: true,
            is_reusable: true,
        }
    } 

    /// Encrypts trivially a clear fhe_string into an encrypted one
    ///
    /// `server_key` a reference to a ServerKey used to encrypt
    /// `padding` the length of the null characters padding to append
    ///  to the string before encryption in order to hide its length
    /// Returns a new encrypted FheString    
    pub fn trivial_encrypt(&self, server_key: &ServerKey, padding: usize) -> Self {
        self.assert_clear("trivial_encrypt");
        // encrypt characters
        let mut fhe_chars = self.chars.iter()
            .map(|c| FheAsciiChar::trivial_encrypt(&c, server_key))
            .collect::<Vec<FheAsciiChar>>();

        // append padding null characters so as to hide its length if padding > 0
        if padding > 0{
            let zero_cst = 0u8 as char;
            let zero_cst_encrypted = FheAsciiChar::trivial_encrypt(&zero_cst, server_key);
            
            let padding_vec = vec![zero_cst_encrypted; padding];
            fhe_chars.extend(padding_vec);
        }

        Self {
            chars: Vec::<char>::new(),
            fhe_chars,
            is_encrypted: true,
            is_padded: padding > 0,
            //is_padded: true,
            is_reusable: true,
        }
    }     


    /// Decrypts an encrypted FheString into a clear FheString
    ///
    /// `client_key` a reference to the RadixClientKey used for decrypting
    /// Returns a clear FheString (with null characters conserved)
    pub fn decrypt(&self, client_key: &RadixClientKey) -> FheString {
        self.assert_encrypted("decrypt");
        // decrypt the FheString as a string and trim the null characters from the end
        let mut chars_str = self
            .fhe_chars
            .iter()
            .map(|fhe_b| fhe_b.decrypt(client_key) as char)
            .collect::<String>();
        chars_str = chars_str.trim_end_matches('\0').to_string();
        // now if the string was supposed to be reusable, panic if we find \0 characters
        if self.is_reusable & chars_str.contains('\0'){
            panic!("The FheString is supposed to be reusable but found non padding \\0 at decryption");
        }
        // remove any \0 remaining:
        chars_str = chars_str.chars().filter(|&c| c != '\0').collect::<String>();
        // convert back to a Vec::<char>
        let chars = chars_str.chars().collect::<Vec<char>>();
        // check that values are ascii
        chars.iter().for_each( |c| {
            assert_is_ascii(&c);
        });
        Self{
            chars,
            fhe_chars: Vec::<FheAsciiChar>::new(),
            is_encrypted: false,
            is_padded: false,
            is_reusable: true,
        }
    }   

    /// Converts a slice of a clear FheString into a String
    ///
    /// `client_key` a reference to the RadixClientKey used for decrypting
    /// Returns a String (with null characters trimmed)
    pub fn slice_to_string(&self, start: usize, end: usize) -> String {
        self.assert_clear("slice_to_string");

        // convert Vec<char> to String and trim the null characters from the end
        let string: String = self.chars[start..end].iter().collect::<String>();
        string
    } 

    /// Converts a clear FheString into a String
    ///
    /// `client_key` a reference to the RadixClientKey used for decrypting
    /// Returns a String (with null characters trimmed)
    pub fn to_string(&self) -> String {
        self.slice_to_string(0, self.len())
    }

    /// Reverses elements of a mutable FheString in place
    /// If it is padded, it will get non reusable
    pub fn reverse(&mut self){
        self.chars.reverse();
        self.fhe_chars.reverse();
        self.is_reusable = !self.is_padded;
    }

    /// Appends trivially encrypted padding to an encrypted FheString
    pub fn pad(&mut self, padding: usize, server_key: &ServerKey){
        self.assert_encrypted("pad");
        if padding > 0{
            let zero_cst = 0u8 as char;
            let zero_cst_encrypted = FheAsciiChar::trivial_encrypt(&zero_cst, server_key);
            
            let mut padding_vec = vec![zero_cst_encrypted; padding];
            self.fhe_chars.append(&mut padding_vec);
            self.is_padded=true;
        }     
    }

    /// Repeat a FheString n times
    /// Warning, if there is padding, the result will not be reusable,
    /// as it will contain empty characters in the string.
    /// Refer to ServerKey::repeat_reusable for getting reusable repeated FheStrings.
    pub fn repeat(&self, n: usize) -> FheString {
        // case not encrypted
        if !self.is_encrypted() {
            return FheString::from_string( &self.to_string().repeat(n) );
        }        
        // case encrypted:
        if n==0 {
            return FheString::empty_encrypted();
        }
        if n== 1 {
            return self.clone();
        }
        let mut fhe_chars = Vec::<FheAsciiChar>::new();
        for i in 0..n {
            let mut clone = self.fhe_chars().clone();
            fhe_chars.append(&mut clone);
        }
        Self{
            chars: Vec::<char>::new(),
            fhe_chars,
            is_encrypted: true,
            is_padded: self.is_padded(),
            is_reusable: !self.is_padded()
        }
    }

    /// Concatenates FheStrings into one
    /// Warning, if there is any padding, the result will not be reusable,
    /// as it will contain empty characters in the string.
    pub fn concatenate(fhe_strings: &Vec<FheString>) -> FheString {
        assert!(fhe_strings.len()>0, "Nothing to concatenate, the vec is empty");
        let mut fhe_chars = Vec::<FheAsciiChar>::new();
        let mut chars = Vec::<char>::new();
        for i in 0..fhe_strings.len(){
            assert!(fhe_strings[0].is_encrypted == fhe_strings[i].is_encrypted(),
                "Trying to concatenate an encrypted FheString with a clear FheString or the opposite"); 
            if fhe_strings[i].is_encrypted(){
                let mut clone = fhe_strings[i].fhe_chars().clone();
                fhe_chars.append(&mut clone);
            }else{
                let mut clone = fhe_strings[i].chars().clone();
                chars.append(&mut clone);
            }
        }
        let is_reusable = if fhe_strings.len()>1 {
            fhe_strings[0..fhe_strings.len()-1].iter().all(|s| !s.is_padded()) 
                && fhe_strings[fhe_strings.len()-1].is_reusable()
        }else{
            fhe_strings[0].is_reusable()
        };
        Self{
            chars,
            fhe_chars,
            is_encrypted: fhe_strings[0].is_encrypted(),
            is_padded: fhe_strings.iter().any(|s| s.is_padded()),
            is_reusable,
        }
    }

    /// Return a reference to the wrapped Vec<char>
    pub (crate) fn chars(&self) -> &Vec<char> {
        self.assert_clear("chars");
        &self.chars
    } 

    /// Return a reference to the wrapped Vec<FheAsciiChar>
    pub (crate) fn fhe_chars(&self) -> &Vec<FheAsciiChar> {
        self.assert_encrypted("fhe_chars");
        &self.fhe_chars
    } 
  
}
