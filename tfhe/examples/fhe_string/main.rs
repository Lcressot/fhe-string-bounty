#![crate_name = "fhe_string"]
#![feature(stmt_expr_attributes)]

//use clap::{App, Arg};
use clap::Parser;
use colored::Colorize;
use std::time::SystemTime;

use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

mod client_key;
mod server_key;
mod ciphertext;

use crate::client_key::ClientKey;
use crate::server_key::ServerKey;

use crate::ciphertext::FheString;

use tfhe::integer::ciphertext::{RadixCiphertext};

pub static NUMBER_OF_BLOCKS: usize = 4; // number of blocks required to encode an ASCII char (8 bits)

fn time_it<F: Fn() -> T, T>(f: F, message: &str) -> T {
    println!("{}", message.bold());
    let start = SystemTime::now();
    let result = f();
    let end = SystemTime::now();
    let duration = end.duration_since(start).unwrap();
    let duration_seconds = duration.as_secs();
    let duration_ms = duration.as_millis() - 1000*(duration_seconds as u128);
    println!("(Took {}.{} seconds)", duration_seconds, duration_ms);
    result
}

fn check_result<T: PartialEq + std::fmt::Display>(result: T, expected: T){
    if result == expected {
        println!("{}, {}", result, "OK!".green());
    } else {
        println!("{}, {} Expected: {}", result, "WRONG!".red(), expected);
    }
    println!("")
}

fn display_block(message: &str){
    println!("{}{}","\n","=".repeat(message.len()+8).bold());
    println!("    {}    ",message.bold());
    println!("{}{}","=".repeat(message.len()+8).bold(), "\n");
}

fn display_sub_block(message: &str){
    println!("\n{}\n",message.bold());
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// String to encrypt
    #[arg(long)]
    string: String,

    /// Pattern to match in the string
    #[arg(long, default_value_t = str::to_string(""))]
    pattern: String,

    /// A second pattern for replace function
    #[arg(long, default_value_t = str::to_string(""))]
    pattern_to: String,    

    /// Padding for the string
    #[arg(long, default_value_t = 0)]
    padding_string: usize,    

    /// Padding for the pattern
    #[arg(long, default_value_t = 0)]
    padding_pattern: usize, 

    /// Padding for the "to" pattern pattern_to
    #[arg(long, default_value_t = 0)]
    padding_to: usize,      

    /// A parameter n, for splitn and replacen
    #[arg(long, default_value_t = 2)]
    n: usize,      

    /// Module to test among:
    /// mod,
    /// partial_ordering,
    /// case,
    /// contains,
    /// find,
    /// trim,
    /// strip,
    /// split,
    /// replace,
    /// repeat
    #[arg(long, default_value_t = str::to_string("all") )]
    module: String,
}

fn main() {
    let args = Args::parse();

    display_sub_block("Computing tests for:");
    println!("string: {}\npadding_string: {}\npattern: {}\npadding_pattern: {}\npattern_to: {}\npadding_to: {}\n n: {}\n",
        args.string, args.padding_string, args.pattern, args.padding_pattern, args.pattern_to, args.padding_to, args.n);

    // Generation of the client/server keys, using the default parameters and 4 blocks for u8:
    let (integer_client_key, integer_server_key) = time_it(
        || gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUMBER_OF_BLOCKS),
        "Generating keys"
    );
    println!("");

    // Wrap client/server keys
    let client_key = ClientKey::new(integer_client_key);
    let server_key = ServerKey::new(integer_server_key);

    // Encrypt the string with given number of null characters padding
    let (encrypted_string, encrypted_pattern, encrypted_pattern_to) = time_it(
        || {
            (client_key.encrypt_str(&args.string, args.padding_string),
            client_key.encrypt_str(&args.pattern, args.padding_pattern),
            client_key.encrypt_str(&args.pattern_to, args.padding_to))
        },
        "Encryting inputs:"
    );
    println!("");

    // create clear fhe_strings
    let clear_string = FheString::from_string(&args.string);
    let clear_pattern = FheString::from_string(&args.pattern);
    let clear_pattern_to = FheString::from_string(&args.pattern_to);

    // testing the encryption/decryption process
    assert!( client_key.decrypt_to_string(&encrypted_string) == args.string , "encryption / decryption of string is wrong");

    if args.module == "mod" || args.module == "all" {

        display_block("mod.rs");

        display_sub_block("is_empty");

        // Compute wether encrypted string is empty  
        let is_empty_encrypted_string = time_it(
            || server_key.is_empty(&encrypted_string),
            "String (encrypted) is empty:"        
            ); 
        check_result( client_key.decrypt_bool(&is_empty_encrypted_string), args.string.is_empty());

        // Compute wether clear string is empty  
        let is_empty_clear_string = time_it(
            || server_key.is_empty(&clear_string),
            "String (clear) is empty:"    
            ); 
        check_result( client_key.decrypt_bool(&is_empty_clear_string), args.string.is_empty());    

        display_sub_block("len");

        // Compute the hidden length of the encrypted fhe_string    
        let hidden_len_encrypted_string = time_it(
            || server_key.len(&encrypted_string),
            "Hidden length of string (encrypted):"        
            ); 
        check_result( client_key.decrypt_u8(&hidden_len_encrypted_string) as usize, args.string.len());

        // Compute the hidden length of the clear fhe_string    
        let hidden_len_clear_string = time_it(
            || server_key.len(&clear_string),
            "Hidden length of string (clear):"        
            ); 
        check_result( client_key.decrypt_u8(&hidden_len_clear_string) as usize, args.string.len());


        display_sub_block("eq");

        // Compute wether encrypted string is equal to encrypted pattern
        let string_equal_encrypted_pattern = time_it(
            || server_key.eq(&encrypted_string, &encrypted_pattern),
            "String (encrypted) equal to pattern (encrypted):"        
            ); 
        check_result( client_key.decrypt_bool(&string_equal_encrypted_pattern), args.string==args.pattern);

        // Compute wether fhe strings are equal to clear other string  
        let string_equal_clear_pattern = time_it(
            || server_key.eq(&encrypted_string, &clear_pattern),
            "String (encrypted) equal to pattern (clear):"        
            ); 
        check_result( client_key.decrypt_bool(&string_equal_clear_pattern), args.string==args.pattern);       

        display_sub_block("ne");

        // Compute wether fhe strings are not equal  
        let string_not_equal_encrypted_pattern = time_it(
            || server_key.ne(&encrypted_string, &encrypted_pattern),
            "String (encrypted) not equal to pattern (encrypted):"        
            ); 
        check_result( client_key.decrypt_bool(&string_not_equal_encrypted_pattern), args.string!=args.pattern);

        // Compute wether fhe string is not equal to clear pattern
        let string_not_equal_clear_pattern = time_it(
            || server_key.ne(&encrypted_string, &clear_pattern),
            "String (encrypted) not equal to clear pattern (clear):"
            ); 
        check_result( client_key.decrypt_bool(&string_not_equal_clear_pattern), args.string!=args.pattern);    
    }

    if args.module == "partial_ordering" || args.module == "all" {

        display_block("partial_ordering.rs");

        display_sub_block("lt");

        // Check if encrypted string is lower than encrypted pattern
        let lt_encrypted_pattern = time_it(
            || server_key.lt(&encrypted_string, &encrypted_pattern),
            "String (encrypted) lower than pattern (encrypted)"
            );
        check_result( client_key.decrypt_bool(&lt_encrypted_pattern), args.string < args.pattern);

        // Check if encrypted string is lower than clear pattern
        let lt_clear_pattern = time_it(
            || server_key.lt(&encrypted_string, &clear_pattern),
            "String (encrypted) lower than pattern (clear)"
            );
        check_result( client_key.decrypt_bool(&lt_clear_pattern), args.string < args.pattern);  

        // Check if encrypted if clear pattern is lower than encrypted string
        // This is to check that the function also work for (clear, encrypted) arguments
        let clear_pattern_lt = time_it(
            || server_key.lt(&clear_pattern, &encrypted_string),
            "Pattern (clear) lower than string (encrypted)"
            );
        check_result( client_key.decrypt_bool(&clear_pattern_lt), args.pattern < args.string);      

        display_sub_block("le");

        // Check if encrypted string is lower or equal to encrypted pattern
        let le_encrypted_pattern = time_it(
            || server_key.le(&encrypted_string, &encrypted_pattern),
            "String (encrypted) lower or equal to pattern (encrypted)"
            );
        check_result( client_key.decrypt_bool(&le_encrypted_pattern), args.string <= args.pattern);    

        // Check if encrypted string is lower or equal to clear pattern
        let le_clear_pattern = time_it(
            || server_key.le(&encrypted_string, &clear_pattern),
            "String (encrypted) lower or equal to pattern (clear)"
            );
        check_result( client_key.decrypt_bool(&le_clear_pattern), args.string <= args.pattern);        

        display_sub_block("gt");

        // Check if encrypted string is greater than encrypted pattern
        let gt_encrypted_pattern = time_it(
            || server_key.gt(&encrypted_string, &encrypted_pattern),
            "String (encrypted) greater than pattern (encrypted)"
            );
        check_result( client_key.decrypt_bool(&gt_encrypted_pattern), args.string > args.pattern);

        // Check if encrypted string is greater than clear pattern
        let gt_clear_pattern = time_it(
            || server_key.gt(&encrypted_string, &clear_pattern),
            "String (encrypted) greater than pattern (clear)"
            );
        check_result( client_key.decrypt_bool(&gt_clear_pattern), args.string > args.pattern);

        display_sub_block("ge");

        // Check if encrypted string is greater or equal to encrypted pattern
        let ge_encrypted_pattern = time_it(
            || server_key.ge(&encrypted_string, &encrypted_pattern),
            "String (encrypted) greater or equal to pattern (encrypted)"
            );
        check_result( client_key.decrypt_bool(&ge_encrypted_pattern), args.string >= args.pattern);     

        // Check if encrypted string is greater or equal to clear pattern
        let ge_clear_pattern = time_it(
            || server_key.ge(&encrypted_string, &clear_pattern),
            "String (encrypted) greater or equal to pattern (clear)"
            );
        check_result( client_key.decrypt_bool(&ge_clear_pattern), args.string >= args.pattern);
    }    

    if args.module == "case" || args.module == "all" {

        display_block("case.rs");

        display_sub_block("to_lower_case");
        // Check if encrypted string is well put to lower case
        let lower_case_string = time_it(
            || server_key.to_lowercase(&encrypted_string),
            "String (encrypted) put to lower case"
            );
        check_result( client_key.decrypt_to_string(&lower_case_string), args.string.to_lowercase() );

        // Check if clear string is well put to lower case
        let lower_case_string_clear = time_it(
            || server_key.to_lowercase(&clear_string),
            "String (clear) put to lower case"
            );
        check_result( lower_case_string_clear.to_string(), args.string.to_lowercase() );    

        display_sub_block("to_upper_case");
        // Check if encrypted string is well put to upper case
        let upper_case_string = time_it(
            || server_key.to_uppercase(&encrypted_string),
            "String (encrypted) put to upper case"
            );
        check_result( client_key.decrypt_to_string(&upper_case_string), args.string.to_uppercase() ); 

        display_sub_block("eq_ignore_case");
        // Check if encrypted string is equal to encrypted pattern while ignoring case
        let string_equal_pattern_ic_encrypted = time_it(
            || server_key.eq_ignore_case(&encrypted_string, &encrypted_pattern),
            "String (encrypted) is equal to pattern (encrypted), ignoring case"
            );
        check_result( client_key.decrypt_bool(&string_equal_pattern_ic_encrypted),
            args.string.to_lowercase() == args.pattern.to_lowercase() ); 
           
        // Check if encrypted string is equal to clear pattern while ignoring case
        let string_equal_pattern_ic_clear = time_it(
            || server_key.eq_ignore_case(&encrypted_string, &clear_pattern),
            "String (encrypted) is equal to pattern (clear), ignoring case"
            );
        check_result( client_key.decrypt_bool(&string_equal_pattern_ic_clear),
            args.string.to_lowercase() == args.pattern.to_lowercase() ); 
    }


    if args.module == "contains" || args.module == "all" {

        display_block("contains.rs");

        display_sub_block("contains");

        // Check if encrypted string contains encrypted pattern
        let contains_encrypted_pattern = time_it(
            || server_key.contains(&encrypted_string, &encrypted_pattern),
            "String (encrypted) contains pattern (encrypted)"
        );
        check_result( client_key.decrypt_bool(&contains_encrypted_pattern),
            args.string.contains( &args.pattern ));

        // Check if encrypted string contains clear pattern
        let contains_clear_pattern = time_it(
            || server_key.contains(&encrypted_string, &clear_pattern),
            "String (encrypted) contains pattern (clear)"
        );
        check_result( client_key.decrypt_bool(&contains_clear_pattern),
            args.string.contains( &args.pattern ));

        // Check if clear string contains encrypted pattern
        let clear_string_contains_encrypted_pattern = time_it(
            || server_key.contains(&clear_string, &encrypted_pattern),
            "String (clear) contains pattern (encrypted)"
        );
        check_result( client_key.decrypt_bool(&clear_string_contains_encrypted_pattern),
            args.string.contains( &args.pattern ));    

        display_sub_block("starts_with");
        // Check if encrypted string starts with encrypted pattern
        let starts_with_encrypted_pattern = time_it(
            || server_key.starts_with(&encrypted_string, &encrypted_pattern),
            "String (encrypted) starts with pattern (encrypted)"
        );
        check_result( client_key.decrypt_bool(&starts_with_encrypted_pattern),
            args.string.starts_with( &args.pattern ));

        // Check if encrypted string starts with clear pattern
        let starts_with_clear_pattern = time_it(
            || server_key.starts_with(&encrypted_string, &clear_pattern),
            "String (encrypted) starts with pattern (clear)"
        );
        check_result( client_key.decrypt_bool(&starts_with_clear_pattern),
            args.string.starts_with( &args.pattern ));

        // Check if clear string starts with encrypted pattern
        let clear_string_starts_with_encrypted_pattern = time_it(
            || server_key.starts_with(&clear_string, &encrypted_pattern),
            "String (clear) starts with pattern (encrypted)"
        );
        check_result( client_key.decrypt_bool(&clear_string_starts_with_encrypted_pattern),
            args.string.starts_with( &args.pattern ));


        display_sub_block("ends_with");
        // Check if encrypted string ends with encrypted pattern
        let ends_with_encrypted_pattern = time_it(
            || server_key.ends_with(&encrypted_string, &encrypted_pattern),
            "String (encrypted) ends with pattern (encrypted)"
        );
        check_result( client_key.decrypt_bool(&ends_with_encrypted_pattern),
            args.string.ends_with( &args.pattern ));

        // Check if encrypted string ends with clear pattern
        let ends_with_clear_pattern = time_it(
            || server_key.ends_with(&encrypted_string, &clear_pattern),
            "String (encrypted) ends with pattern (clear)"
        );
        check_result( client_key.decrypt_bool(&ends_with_clear_pattern),
            args.string.ends_with( &args.pattern ));

        // Check if clear string ends with encrypted pattern
        let clear_string_ends_with_encrypted_pattern = time_it(
            || server_key.ends_with(&clear_string, &encrypted_pattern),
            "String (clear) ends with pattern (encrypted)"
        );
        check_result( client_key.decrypt_bool(&clear_string_ends_with_encrypted_pattern),
            args.string.ends_with( &args.pattern ));

    }

    if args.module == "find" || args.module == "all" {


        display_sub_block("find");

        // Check if encrypted string finds encrypted pattern
        let (find_with_encrypted_pattern, found_encrypted_pattern) = time_it(
            || server_key.find(&encrypted_string, &encrypted_pattern),
            "String (encrypted) finds pattern (encrypted)"
        );
        match args.string.find( &args.pattern ){
            Some(index) => check_result(client_key.decrypt_u64(&find_with_encrypted_pattern), index as u64),
            None => check_result( client_key.decrypt_bool(&found_encrypted_pattern), false),
        };

        // Check if encrypted string finds clear pattern
        let (find_clear_pattern, found_clear_pattern) = time_it(
            || server_key.find(&encrypted_string, &clear_pattern),
            "String (encrypted) finds pattern (clear)"
        );
        match args.string.find( &args.pattern ){
            Some(index) => check_result(client_key.decrypt_u64(&find_clear_pattern), index as u64),
            None => check_result( client_key.decrypt_bool(&found_clear_pattern), false),
        };
        // Check if clear string finds encrypted pattern
        let (clear_string_find_encrypted_pattern, found_clear_string_encrypted_pattern) = time_it(
            || server_key.find(&clear_string, &encrypted_pattern),
            "String (clear) finds pattern (encrypted)"
        );
        match args.string.find( &args.pattern ){
            Some(index) => check_result(client_key.decrypt_u64(&clear_string_find_encrypted_pattern), index as u64),
            None => check_result( client_key.decrypt_bool(&found_clear_string_encrypted_pattern), false),
        };

        display_sub_block("rfind");

        // Check if encrypted string rfinds encrypted pattern
        let (rfind_with_encrypted_pattern, found_encrypted_pattern) = time_it(
            || server_key.rfind(&encrypted_string, &encrypted_pattern),
            "String (encrypted) rfinds pattern (encrypted)"
        );
        match args.string.rfind( &args.pattern ){
            Some(index) => check_result(client_key.decrypt_u64(&rfind_with_encrypted_pattern), index as u64),
            None => check_result( client_key.decrypt_bool(&found_encrypted_pattern), false),
        };

        // Check if encrypted string rfinds clear pattern
        let (rfind_clear_pattern, found_clear_pattern) = time_it(
            || server_key.rfind(&encrypted_string, &clear_pattern),
            "String (encrypted) rfinds pattern (clear)"
        );
        match args.string.rfind( &args.pattern ){
            Some(index) => check_result(client_key.decrypt_u64(&rfind_clear_pattern), index as u64),
            None => check_result( client_key.decrypt_bool(&found_clear_pattern), false),
        };

        // Check if clear string rfinds encrypted pattern
        let (clear_string_rfind_encrypted_pattern, found_clear_string_encrypted_pattern) = time_it(
            || server_key.rfind(&clear_string, &encrypted_pattern),
            "String (clear) rfinds pattern (encrypted)"
        );
        match args.string.rfind( &args.pattern ){
            Some(index) => check_result(client_key.decrypt_u64(&clear_string_rfind_encrypted_pattern), index as u64),
            None => check_result( client_key.decrypt_bool(&found_clear_string_encrypted_pattern), false),
        }; 

    }

    if args.module == "trim" || args.module == "all" {
   
        display_block("trim.rs");

        display_sub_block("trim start");

        // Trim start encrypted string
        let trim_encrypted_string = time_it(
            || server_key.trim_start(&encrypted_string),
            "String (encrypted) trimmed start"
        );
        check_result( client_key.decrypt_to_string(&trim_encrypted_string), args.string.trim_start().to_string());

        // Trim start clear string
        let trim_clear_string = time_it(
            || server_key.trim_start(&clear_string),
            "String (clear) trimmed start"
        );
        check_result( trim_clear_string.to_string(), args.string.trim_start().to_string());


        display_sub_block("trim start reusable");

        // Trim start encrypted string for reusable
        let trim_encrypted_string_reusable = time_it(
            || server_key.trim_start_reusable(&encrypted_string),
            "String (encrypted) trimmed start (reusable)"
        );
        assert!(trim_encrypted_string_reusable.is_reusable());
        check_result( client_key.decrypt_to_string(&trim_encrypted_string_reusable), args.string.trim_start().to_string());

        display_sub_block("trim end");

        // Trim end encrypted string
        let trim_encrypted_string = time_it(
            || server_key.trim_end(&encrypted_string),
            "String (encrypted) trimmed end"
        );
        check_result( client_key.decrypt_to_string(&trim_encrypted_string), args.string.trim_end().to_string());

        // Trim end clear string
        let trim_clear_string = time_it(
            || server_key.trim_end(&clear_string),
            "String (clear) trimmed end"
        );
        check_result( trim_clear_string.to_string(), args.string.trim_end().to_string());


        display_sub_block("trim");    

        // Trim encrypted string
        let trim_encrypted_string = time_it(
            || server_key.trim(&encrypted_string),
            "String (encrypted) trimmed"
        );
        check_result( client_key.decrypt_to_string(&trim_encrypted_string), args.string.trim().to_string());

        // Trim clear string
        let trim_clear_string = time_it(
            || server_key.trim(&clear_string),
            "String (clear) trimmed"
        );
        check_result( trim_clear_string.to_string(), args.string.trim().to_string());

        display_sub_block("trim reusable");    

        // Trim encrypted string
        let trim_encrypted_string_reusable = time_it(
            || server_key.trim_reusable(&encrypted_string),
            "String (encrypted) trimmed (reusable)"
        );
        assert!(trim_encrypted_string_reusable.is_reusable());
        check_result( client_key.decrypt_to_string(&trim_encrypted_string_reusable), args.string.trim().to_string());

        // Trim clear string
        let trim_clear_string_reusable = time_it(
            || server_key.trim_reusable(&clear_string),
            "String (clear) trimmed (reusable)"
        );
        assert!(trim_clear_string_reusable.is_reusable());
        check_result( trim_clear_string_reusable.to_string(), args.string.trim().to_string());

    }

    if args.module == "strip" || args.module == "all" {

        display_sub_block("strip prefix");

        let check_strip_prefix = | string: &FheString, pattern: &FheString, message: &String |{
            // Strip prefix from string
            let (strip_pattern_from_string, stripped) = time_it(
                || server_key.strip_prefix(string, pattern),
                message.as_str()
            );
            match args.string.strip_prefix(&args.pattern) {
                Some(string) => {
                    match strip_pattern_from_string.is_encrypted(){
                        true => check_result( client_key.decrypt_to_string(&strip_pattern_from_string), string.to_string() ),
                        false => check_result( strip_pattern_from_string.to_string(), string.to_string() )
                    };
                    check_result( client_key.decrypt_bool(&stripped), true);
                },
                None => {
                    match strip_pattern_from_string.is_encrypted(){
                        true => check_result( client_key.decrypt_to_string(&strip_pattern_from_string), args.string.clone() ),
                        false => check_result( strip_pattern_from_string.to_string(), args.string.clone() )
                    };
                    check_result( client_key.decrypt_bool(&stripped), false);
                }
            };
        };

        check_strip_prefix( &encrypted_string, &encrypted_pattern, &"String (encrypted) stripped of prefix pattern (encrypted)".to_string());
        check_strip_prefix( &clear_string, &encrypted_pattern, &"String (clear) stripped of prefix pattern (encrypted) ".to_string());
        check_strip_prefix( &encrypted_string, &clear_pattern, &"String (encrypted) stripped of prefix pattern (clear)".to_string());
        check_strip_prefix( &clear_string, &clear_pattern, &"String (clear) stripped of prefix pattern (clear)".to_string());

        display_sub_block("strip prefix reusable");

        let check_strip_prefix_reusable = | string: &FheString, pattern: &FheString, message: &String |{
            // Strip prefix from string
            let (strip_pattern_from_string, stripped) = time_it(
                || server_key.strip_prefix_reusable(string, pattern),
                message.as_str()
            );
            assert!(strip_pattern_from_string.is_reusable());
            match args.string.strip_prefix(&args.pattern) {
                Some(string) => {
                    match strip_pattern_from_string.is_encrypted(){
                        true => check_result( client_key.decrypt_to_string(&strip_pattern_from_string), string.to_string() ),
                        false => check_result( strip_pattern_from_string.to_string(), string.to_string() )
                    };
                    check_result( client_key.decrypt_bool(&stripped), true);
                },
                None => {
                    match strip_pattern_from_string.is_encrypted(){
                        true => check_result( client_key.decrypt_to_string(&strip_pattern_from_string), args.string.clone() ),
                        false => check_result( strip_pattern_from_string.to_string(), args.string.clone() )
                    };
                    check_result( client_key.decrypt_bool(&stripped), false);
                }
            };
        };

        check_strip_prefix_reusable( &encrypted_string, &encrypted_pattern, &"String (encrypted) stripped (reusable) of prefix pattern (encrypted)".to_string());
        check_strip_prefix_reusable( &clear_string, &encrypted_pattern, &"String (clear) stripped (reusable) of prefix pattern (encrypted) ".to_string());
        check_strip_prefix_reusable( &encrypted_string, &clear_pattern, &"String (encrypted) stripped (reusable) of prefix pattern (clear)".to_string());
        check_strip_prefix_reusable( &clear_string, &clear_pattern, &"String (clear) stripped (reusable) of prefix pattern (clear)".to_string());

        display_sub_block("strip suffix");

        let check_strip_suffix = | string: &FheString, pattern: &FheString, message: &String |{
            // Strip suffix from string
            let (strip_pattern_from_string, stripped) = time_it(
                || server_key.strip_suffix(string, pattern),
                message.as_str()
            );
            match args.string.strip_suffix(&args.pattern) {
                Some(string) => {
                    match strip_pattern_from_string.is_encrypted(){
                        true => check_result( client_key.decrypt_to_string(&strip_pattern_from_string), string.to_string() ),
                        false => check_result( strip_pattern_from_string.to_string(), string.to_string() )
                    };
                    check_result( client_key.decrypt_bool(&stripped), true); 
                },
                None => {
                    match strip_pattern_from_string.is_encrypted(){
                        true => check_result( client_key.decrypt_to_string(&strip_pattern_from_string), args.string.clone() ),
                        false => check_result( strip_pattern_from_string.to_string(), args.string.clone() )
                    };
                    check_result( client_key.decrypt_bool(&stripped), false);
                },
            };
        };

        check_strip_suffix( &encrypted_string, &encrypted_pattern, &"String (encrypted) stripped of suffix pattern (encrypted)".to_string());
        check_strip_suffix( &clear_string, &encrypted_pattern, &"String (clear) stripped of suffix pattern (encrypted) ".to_string());
        check_strip_suffix( &encrypted_string, &clear_pattern, &"String (encrypted) stripped of suffix pattern (clear)".to_string());
        check_strip_suffix( &clear_string, &clear_pattern, &"String (clear) stripped of suffix pattern (clear)".to_string());

    }

    if args.module == "split" || args.module == "all" {

        display_block("split.rs");

        let check_split_all = | split_vec: Vec::<FheString>, n_fields: RadixCiphertext, split_vec_clear: Vec::<String>, message: &String |{

            // first check if the number of fields is correct
            let expected_n_fields = split_vec_clear.len() as usize;
            let actual_n_fields = client_key.decrypt_u64(&n_fields) as usize;
            if actual_n_fields != expected_n_fields {
                println!("{}  Number of fields incorrect. Expected : {}, Actual: {}", "WRONG!".red(), expected_n_fields, actual_n_fields);
            }

            // then check the fields
            for i in 0..actual_n_fields{
                let clear_split = split_vec_clear[i].clone();
                let decrypted_split = client_key.decrypt_to_string(&split_vec[i]);

                let clear_split_msg = "CLEAR: \"".to_string() + &clear_split + &"\"";
                let decrypted_split_msg = "FHE: \"".to_string() + &decrypted_split + &"\"";
                let result = match clear_split==decrypted_split{
                    true => "OK!".green(),
                    false => "WRONG!".red()
                };
               
                let repeated_space: String = std::iter::repeat(' ').take(40 - decrypted_split.len()).collect();
                let repeated_space_2: String = std::iter::repeat(' ').take(40 - clear_split_msg.len()).collect();
                println!("{}{}|   {}    {}{}", decrypted_split_msg, repeated_space, clear_split_msg, repeated_space_2, result);
            }   
        }; 

        let check_split_all_clear = | split_vec: Vec::<FheString>, n_fields: RadixCiphertext, split_vec_clear: Vec::<String>, message: &String |{

            // first check if the number of fields is correct
            let expected_n_fields = split_vec_clear.len() as usize;
            let actual_n_fields = client_key.decrypt_u64(&n_fields) as usize;
            if actual_n_fields != expected_n_fields {
                println!("{}  Number of fields incorrect. Expected : {}, Actual: {}", "WRONG!".red(), expected_n_fields, actual_n_fields);
            }

            // then check the fields
            for i in 0..actual_n_fields{
                let clear_split = split_vec_clear[i].clone();
                let decoded_split = split_vec[i].to_string();

                let clear_split_msg = "CLEAR: \"".to_string() + &clear_split + &"\"";
                let decoded_split_msg = "FHE: \"".to_string() + &decoded_split + &"\"";
                let result = match clear_split==decoded_split{
                    true => "OK!".green(),
                    false => "WRONG!".red()
                };
               
                let repeated_space: String = std::iter::repeat(' ').take(40 - decoded_split.len()).collect();
                let repeated_space_2: String = std::iter::repeat(' ').take(40 - clear_split_msg.len()).collect();
                println!("{}{}|   {}    {}{}", decoded_split_msg, repeated_space, clear_split_msg, repeated_space_2, result);
            }   
        };       

        display_sub_block("split");        

        let check_split = | string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, n_fields) = time_it(
                || server_key.split(string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().split(&args.pattern).map(|s| s.to_string()).collect();

            if split_vec[0].is_encrypted(){
                check_split_all(split_vec, n_fields, split_vec_clear, message);
            }else{
                check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }
        };       

        check_split(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) split for pattern (encrypted)".to_string(),
        );

        check_split(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) split for pattern (encrypted)".to_string(),
        );

        check_split(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) split for pattern (clear)".to_string(),
        );    

        check_split(
            &clear_string,
            &clear_pattern,
            &"String (clear) split for pattern (clear)".to_string(),
        );

        let check_split_reusable = | string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, n_fields) = time_it(
                || server_key.split_reusable(string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().split(&args.pattern).map(|s| s.to_string()).collect();

            split_vec.iter().for_each(|split_str| assert!(split_str.is_reusable()) );
            
            if split_vec[0].is_encrypted(){
                check_split_all(split_vec, n_fields, split_vec_clear, message);
            }else{
                check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }
        };        

        check_split_reusable(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) split_reusable for pattern (encrypted)".to_string(),
        );

        // check_split_reusable(
        //     &clear_string,
        //     &encrypted_pattern,
        //     &"String (clear) split_reusable for pattern (encrypted)".to_string(),
        // ); 

        // check_split_reusable(
        //     &encrypted_string,
        //     &clear_pattern,
        //     &"String (encrypted) split_reusable for pattern (clear)".to_string(),
        // );       

        display_sub_block("rsplit");

        let check_rsplit = | string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, n_fields) = time_it(
                || server_key.rsplit(string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().rsplit(&args.pattern).map(|s| s.to_string()).collect();

            if split_vec[0].is_encrypted(){
                check_split_all(split_vec, n_fields, split_vec_clear, message);
            }else{
                check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }
        };            

        check_rsplit(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) rsplit for pattern (encrypted)".to_string(),
        );       

        check_rsplit(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) rsplit for pattern (encrypted)".to_string(),
        );  

        check_rsplit(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) rsplit for pattern (clear)".to_string(),
        );       

        check_rsplit(
            &clear_string,
            &clear_pattern,
            &"String (clear) rsplit for pattern (clear)".to_string(),
        );            

        display_sub_block("split_n");
        
        let check_split_n = | n_times: usize, string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, n_fields) = time_it(
                || server_key.splitn(n_times, string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().splitn(n_times, &args.pattern).map(|s| s.to_string()).collect();

            if split_vec.len() >0 {
                if split_vec[0].is_encrypted(){
                    check_split_all(split_vec, n_fields, split_vec_clear, message);
                }else{
                    check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }}else{
                if split_vec_clear.len()==0{
                    println!("{} {}", "Result empty  ".white(), "OK!".green());
                }else{
                    println!("{} {}", "Result empty  ".white(), "WRONG!".red());
                }
            }            
        };

        check_split_n(
            args.n,
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) splitn for pattern (encrypted)".to_string(),
        );

        check_split_n(
            args.n,
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) splitn for pattern (clear)".to_string(),
        );

        check_split_n(
            args.n,
            &clear_string,
            &encrypted_pattern,
            &"String (clear) splitn for pattern (encrypted)".to_string(),
        );

        check_split_n(
            args.n,
            &clear_string,
            &clear_pattern,
            &"String (clear) splitn for pattern (clear)".to_string(),
        ); 



        display_sub_block("rsplitn");
        
        let check_rsplit_n = | n_times: usize, string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, n_fields) = time_it(
                || server_key.rsplitn(n_times, string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().rsplitn(n_times, &args.pattern).map(|s| s.to_string()).collect();

            if split_vec.len() >0 {
                if split_vec[0].is_encrypted(){
                    check_split_all(split_vec, n_fields, split_vec_clear, message);
                }else{
                    check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }}else{
                if split_vec_clear.len()==0{
                    println!("{} {}", "Result empty  ".white(), "OK!".green());
                }else{
                    println!("{} {}", "Result empty  ".white(), "WRONG!".red());
                }
            }   
        };

        check_rsplit_n(
            args.n,
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) rsplitn for pattern (encrypted)".to_string(),
        );

        check_rsplit_n(
            args.n,
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) rsplitn for pattern (clear)".to_string(),
        );

        check_rsplit_n(
            args.n,
            &clear_string,
            &encrypted_pattern,
            &"String (clear) rsplitn for pattern (encrypted)".to_string(),
        );

        check_rsplit_n(
            args.n,
            &clear_string,
            &clear_pattern,
            &"String (clear) rsplitn for pattern (clear)".to_string(),
        ); 


        display_sub_block("split_once");
        
        let check_split_once = | string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, found) :( Vec::<FheString>, RadixCiphertext) = time_it(
                || server_key.split_once(string, pattern),
                message.as_str()
            );
            match args.string.to_string().split_once( &args.pattern){
                None => {
                    match client_key.decrypt_bool(&found){
                        true => println!("{} {}", "Pattern found  ".white(), "WRONG!".red()),
                        false => println!("{} {}", "Pattern not found  ".white(), "OK!".green())
                    };
                    match split_vec.len(){
                        0 => println!("{} {}", "Nothing returned  ".white(), "OK!".green()),
                        _ => println!("{} {}", "Something returned  ".white(), "WRONG!".red())
                    };                 
                },
                Some((v1, v2)) => match client_key.decrypt_bool(&found){
                        true => {
                            let mut vec_str = Vec::<String>::new();
                            vec_str.push(v1.to_string());
                            vec_str.push(v2.to_string());

                            if split_vec[0].is_encrypted(){
                                check_split_all(split_vec, client_key.encrypt_u8(&2u8), vec_str, message);
                            }else{
                                check_split_all_clear(split_vec, client_key.encrypt_u8(&2u8), vec_str, message);
                            }                            
                        },                        
                        false => println!("{} {}", "Pattern not found  ".white(), "WRONG!".red())
                    }
            };
        };

        check_split_once(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) split_once for pattern (encrypted)".to_string(),
        ); 

        check_split_once(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) split_once for pattern (clear)".to_string(),
        ); 

        check_split_once(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) split_once for pattern (encrypted)".to_string(),
        ); 

        check_split_once(
            &clear_string,
            &clear_pattern,
            &"String (clear) split_once for pattern (clear)".to_string(),
        );          

        display_sub_block("rsplit_once");

        let check_rsplit_once = | string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, found) :( Vec::<FheString>, RadixCiphertext) = time_it(
                || server_key.rsplit_once( string, pattern),
                message.as_str()
            );
            match args.string.to_string().rsplit_once( &args.pattern){
                None => {
                    match client_key.decrypt_bool(&found){
                        true => println!("{} {}", "Pattern found  ".white(), "WRONG!".red()),
                        false => println!("{} {}", "Pattern not found  ".white(), "OK!".green())
                    };
                    match split_vec.len(){
                        0 => println!("{} {}", "Nothing returned  ".white(), "OK!".green()),
                        _ => println!("{} {}", "Something returned  ".white(), "WRONG!".red())
                    };                   
                },
                Some((v1, v2)) => match client_key.decrypt_bool(&found){
                        true => {
                            let mut vec_str = Vec::<String>::new();
                            vec_str.push(v1.to_string());
                            vec_str.push(v2.to_string());
                            
                            if split_vec[0].is_encrypted(){
                                check_split_all(split_vec, client_key.encrypt_u8(&2u8), vec_str, message);
                            }else{
                                check_split_all_clear(split_vec, client_key.encrypt_u8(&2u8), vec_str, message);
                            }     
                        },
                        false => println!("{} {}", "Pattern not found  ".white(), "WRONG!".red())
                    }
            };
        };

        check_rsplit_once(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) rsplit_once for pattern (encrypted)".to_string(),
        ); 

        check_rsplit_once(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) rsplit_once for pattern (clear)".to_string(),
        ); 

        check_rsplit_once(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) rsplit_once for pattern (encrypted)".to_string(),
        ); 

        check_rsplit_once(
            &clear_string,
            &clear_pattern,
            &"String (clear) rsplit_once for pattern (clear)".to_string(),
        );  


        display_sub_block("split_inclusive");        

        let check_split_inclusive = | string: &FheString, pattern: &FheString, message: &String |{

            let (split_vec, n_fields) = time_it(
                || server_key.split_inclusive(string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().split_inclusive(&args.pattern).map(|s| s.to_string()).collect();

            if split_vec.len() >0 {
                if split_vec[0].is_encrypted(){
                    check_split_all(split_vec, n_fields, split_vec_clear, message);
                }else{
                    check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }}else{
                if split_vec_clear.len()==0{
                    println!("{} {}", "Result empty  ".white(), "OK!".green());
                }else{
                    println!("{} {}", "Result empty  ".white(), "WRONG!".red());
                }
            }               
        };         

        check_split_inclusive(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) split_inclusive for pattern (encrypted)".to_string(),
        );

        check_split_inclusive(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) split_inclusive for pattern (encrypted)".to_string(),
        ); 

        check_split_inclusive(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) split_inclusive for pattern (clear)".to_string(),
        );    

        check_split_inclusive(
            &clear_string,
            &clear_pattern,
            &"String (clear) split_inclusive for pattern (clear)".to_string(),
        );


        display_sub_block("split_terminator");        

        let check_split_terminator = | string: &FheString, pattern: &FheString, message: &String|{

            let (split_vec, n_fields) = time_it(
                || server_key.split_terminator(string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().split_terminator(&args.pattern).map(|s| s.to_string()).collect();

            if split_vec.len() >0 {
                if split_vec[0].is_encrypted(){
                    check_split_all(split_vec, n_fields, split_vec_clear, message);
                }else{
                    check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }}else{
                if split_vec_clear.len()==0{
                    println!("{} {}", "Result empty  ".white(), "OK!".green());
                }else{
                    println!("{} {}", "Result empty  ".white(), "WRONG!".red());
                }
            }  
        };         

        check_split_terminator(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) split_terminator for pattern (encrypted)".to_string(),
        );

        check_split_terminator(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) split_terminator for pattern (encrypted)".to_string(),
        );

        check_split_terminator(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) split_terminator for pattern (clear)".to_string(),
        );    

        check_split_terminator(
            &clear_string,
            &clear_pattern,
            &"String (clear) split_terminator for pattern (clear)".to_string()
        );        


        display_sub_block("rsplit_terminator");        

        let check_rsplit_terminator = | string: &FheString, pattern: &FheString, message: &String|{

            let (split_vec, n_fields) = time_it(
                || server_key.rsplit_terminator(string, pattern),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().rsplit_terminator(&args.pattern).map(|s| s.to_string()).collect();

            if split_vec.len() >0 {
                if split_vec[0].is_encrypted(){
                    check_split_all(split_vec, n_fields, split_vec_clear, message);
                }else{
                    check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }}else{
                if split_vec_clear.len()==0{
                    println!("{} {}", "Result empty  ".white(), "OK!".green());
                }else{
                    println!("{} {}", "Result empty  ".white(), "WRONG!".red());
                }
            }  
        };      

        check_rsplit_terminator(
            &encrypted_string,
            &encrypted_pattern,
            &"String (encrypted) rsplit_terminator for pattern (encrypted)".to_string(),
        );

        check_rsplit_terminator(
            &clear_string,
            &encrypted_pattern,
            &"String (clear) rsplit_terminator for pattern (encrypted)".to_string(),
        );

        check_rsplit_terminator(
            &encrypted_string,
            &clear_pattern,
            &"String (encrypted) rsplit_terminator for pattern (clear)".to_string(),
        );    

        check_rsplit_terminator(
            &clear_string,
            &clear_pattern,
            &"String (clear) rsplit_terminator for pattern (clear)".to_string()
        );                


        display_sub_block("split_ascii_whitespace");        

        let check_split_ascii_whitespace = | string: &FheString, message: &String|{

            let (split_vec, n_fields) = time_it(
                || server_key.split_ascii_whitespace(string),
                message.as_str()
            );
            let split_vec_clear : Vec::<String> = args.string.to_string().split_ascii_whitespace().map(|s| s.to_string()).collect();

            if split_vec.len() >0 {
                if split_vec[0].is_encrypted(){
                    check_split_all(split_vec, n_fields, split_vec_clear, message);
                }else{
                    check_split_all_clear(split_vec, n_fields, split_vec_clear, message);
            }}else{
                if split_vec_clear.len()==0{
                    println!("{} {}", "Result empty  ".white(), "OK!".green());
                }else{
                    println!("{} {}", "Result empty  ".white(), "WRONG!".red());
                }
            }
        };

        check_split_ascii_whitespace(
            &encrypted_string,
            &"String (encrypted) split_ascii_whitespace".to_string(),
        );

        check_split_ascii_whitespace(
            &clear_string,
            &"String (clear) split_ascii_whitespace".to_string(),
        );


    }

    if args.module == "replace" || args.module == "all" {

        display_block("replace.rs");

        display_sub_block("replace");

        let replace_ground_truth = args.string.replace(&args.pattern, &args.pattern_to).to_string();

        let check_replace = |fhe_string: &FheString, ground_truth: &String|{
            if fhe_string.is_encrypted(){
                check_result( client_key.decrypt_to_string(&fhe_string), ground_truth.clone());
            }else{
                check_result( fhe_string.to_string(), ground_truth.clone());
            }
        };

        let replace_clear_string_clear_clear = time_it(
            || server_key.replace(&clear_string, &clear_pattern, &clear_pattern_to),
            "String (clear) replace with pattern (clear) and pattern_to (clear)"
        );
        check_result( replace_clear_string_clear_clear.to_string(), replace_ground_truth.clone());

        let replace_clear_string_clear_encrypted = time_it(
            || server_key.replace(&clear_string, &clear_pattern, &encrypted_pattern_to),
            "String (clear) replace with pattern (clear) and pattern_to (encrypted)"
        );
        check_replace(&replace_clear_string_clear_encrypted, &replace_ground_truth);

        let replace_clear_string_encrypted_clear = time_it(
            || server_key.replace(&clear_string, &encrypted_pattern, &clear_pattern_to),
            "String (clear) replace with pattern (encrypted) and pattern_to (clear)"
        );
        check_replace(&replace_clear_string_encrypted_clear, &replace_ground_truth);    

        let replace_clear_string_encrypted_encrypted = time_it(
            || server_key.replace(&clear_string, &encrypted_pattern, &encrypted_pattern_to),
            "String (clear) replace with pattern (encrypted) and pattern_to (encrypted)"
        );
        check_replace(&replace_clear_string_encrypted_encrypted, &replace_ground_truth);    

        let replace_encrypted_string_clear_clear = time_it(
            || server_key.replace(&encrypted_string, &clear_pattern, &clear_pattern_to),
            "String (encrypted) replace with pattern (clear) and pattern_to (clear)"
        );
        check_replace(&replace_encrypted_string_clear_clear, &replace_ground_truth);

        let replace_encrypted_string_clear_encrypted = time_it(
            || server_key.replace(&encrypted_string, &clear_pattern, &encrypted_pattern_to),
            "String (encrypted) replace with pattern (clear) and pattern_to (encrypted)"
        );
        check_replace(&replace_encrypted_string_clear_encrypted, &replace_ground_truth);

        let replace_encrypted_string_encrypted_clear = time_it(
            || server_key.replace(&encrypted_string, &encrypted_pattern, &clear_pattern_to),
            "String (encrypted) replace with pattern (encrypted) and pattern_to (clear)"
        );
        check_replace(&replace_encrypted_string_encrypted_clear, &replace_ground_truth);    

        let replace_encrypted_string_encrypted_encrypted = time_it(
            || server_key.replace(&encrypted_string, &encrypted_pattern, &encrypted_pattern_to),
            "String (encrypted) replace with pattern (encrypted) and pattern_to (encrypted)"
        );
        check_replace(&replace_encrypted_string_encrypted_encrypted, &replace_ground_truth);    

        let replace_reusable_encrypted_string_encrypted_encrypted = time_it(
            || server_key.replace_reusable(&encrypted_string, &encrypted_pattern, &encrypted_pattern_to),
            "String (encrypted) replace reusable with pattern (encrypted) and pattern_to (encrypted)"
        );
        assert!(replace_reusable_encrypted_string_encrypted_encrypted.is_reusable());
        check_replace(&replace_reusable_encrypted_string_encrypted_encrypted, &replace_ground_truth);    

 

        display_sub_block("replacen");

        let replacen_ground_truth = args.string.replacen(&args.pattern, &args.pattern_to, args.n).to_string();

        let check_replacen = |fhe_string: &FheString, ground_truth: &String|{
            if fhe_string.is_encrypted(){
                check_result( client_key.decrypt_to_string(&fhe_string), ground_truth.clone());
            }else{
                check_result( fhe_string.to_string(), ground_truth.clone());
            }
        };

        let replacen_clear_string_clear_clear = time_it(
            || server_key.replacen(&clear_string, &clear_pattern, &clear_pattern_to, args.n),
            "String (clear) replacen with pattern (clear) and pattern_to (clear)"
        );
        check_result( replacen_clear_string_clear_clear.to_string(), replacen_ground_truth.clone());

        let replacen_clear_string_clear_encrypted = time_it(
            || server_key.replacen(&clear_string, &clear_pattern, &encrypted_pattern_to, args.n),
            "String (clear) replacen with pattern (clear) and pattern_to (encrypted)"
        );
        check_replacen(&replacen_clear_string_clear_encrypted, &replacen_ground_truth);

        let replacen_clear_string_encrypted_clear = time_it(
            || server_key.replacen(&clear_string, &encrypted_pattern, &clear_pattern_to, args.n),
            "String (clear) replacen with pattern (encrypted) and pattern_to (clear)"
        );
        check_replacen(&replacen_clear_string_encrypted_clear, &replacen_ground_truth);    

        let replacen_clear_string_encrypted_encrypted = time_it(
            || server_key.replacen(&clear_string, &encrypted_pattern, &encrypted_pattern_to, args.n),
            "String (clear) replacen with pattern (encrypted) and pattern_to (encrypted)"
        );
        check_replacen(&replacen_clear_string_encrypted_encrypted, &replacen_ground_truth);    


        let replacen_encrypted_string_clear_clear = time_it(
            || server_key.replacen(&encrypted_string, &clear_pattern, &clear_pattern_to, args.n),
            "String (encrypted) replacen with pattern (clear) and pattern_to (clear)"
        );
        check_replacen(&replacen_encrypted_string_clear_clear, &replacen_ground_truth);

        let replacen_encrypted_string_clear_encrypted = time_it(
            || server_key.replacen(&encrypted_string, &clear_pattern, &encrypted_pattern_to, args.n),
            "String (encrypted) replacen with pattern (clear) and pattern_to (encrypted)"
        );
        check_replacen(&replacen_encrypted_string_clear_encrypted, &replacen_ground_truth);

        let replacen_encrypted_string_encrypted_clear = time_it(
            || server_key.replacen(&encrypted_string, &encrypted_pattern, &clear_pattern_to, args.n),
            "String (encrypted) replacen with pattern (encrypted) and pattern_to (clear)"
        );
        check_replacen(&replacen_encrypted_string_encrypted_clear, &replacen_ground_truth);    

        let replacen_encrypted_string_encrypted_encrypted = time_it(
            || server_key.replacen(&encrypted_string, &encrypted_pattern, &encrypted_pattern_to, args.n),
            "String (encrypted) replacen with pattern (encrypted) and pattern_to (encrypted)"
        );
        check_replacen(&replacen_encrypted_string_encrypted_encrypted, &replacen_ground_truth);                   

        let replacen_reusable_encrypted_string_encrypted_encrypted = time_it(
            || server_key.replacen_reusable(&encrypted_string, &encrypted_pattern, &encrypted_pattern_to, args.n),
            "String (encrypted) replacen_reusable with pattern (encrypted) and pattern_to (encrypted)"
        );
        check_replacen(&replacen_reusable_encrypted_string_encrypted_encrypted, &replacen_ground_truth);                   

    }

    if args.module == "repeat" || args.module == "all" {

        display_block("repeat.rs");

        display_block("repeat");

        let repeat_ground_truth = args.string.repeat(args.n);

        let repeat_clear_string = time_it(
            || server_key.repeat(&clear_string, args.n),
            "String (clear) repeat"
        );
        check_result(&repeat_clear_string.to_string(), &repeat_ground_truth);

        let repeat_encrypted_string = time_it(
            || server_key.repeat(&encrypted_string, args.n),
            "String (encrypted) repeat"
        );
        check_result(&client_key.decrypt_to_string(&repeat_encrypted_string), &repeat_ground_truth);

        display_block("repeat_reusable");

        let repeat_reusable_clear_string = time_it(
            || server_key.repeat_reusable(&clear_string, args.n),
            "String (clear) repeat_reusable"
        );
        assert!(clear_string.is_reusable());
        check_result(&repeat_reusable_clear_string.to_string(), &repeat_ground_truth);

        let repeat_reusable_encrypted_string = time_it(
            || server_key.repeat_reusable(&encrypted_string, args.n),
            "String (encrypted) repeat_reusable"
        );
        assert!(repeat_reusable_encrypted_string.is_reusable());
        check_result(&client_key.decrypt_to_string(&repeat_reusable_encrypted_string), &repeat_ground_truth);        

    }

}