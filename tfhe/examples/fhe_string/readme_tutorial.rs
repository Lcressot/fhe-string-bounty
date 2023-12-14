#![crate_name = "fhe_str"]
#![feature(stmt_expr_attributes)]


use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

mod client_key;
mod server_key;
mod ciphertext;

use crate::client_key::ClientKey;
use crate::server_key::ServerKey;

use crate::ciphertext::FheString;


// number of blocks required to encode an ASCII char (8 bits)
pub static NUMBER_OF_BLOCKS: usize = 4;

fn main() {
    // Generation of the client/server keys, using the default parameters and 4 blocks for u8:
    let (integer_client_key, integer_server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUMBER_OF_BLOCKS);

    // Wrap client/server keys
    let client_key = ClientKey::new(integer_client_key);
    let server_key = ServerKey::new(integer_server_key);


    // create clear string
    let clear_string = FheString::from_str("Hello");
    let clear_string2 = FheString::from_string(&"Hello".to_string());

    assert_eq!(clear_string.is_clear(), true);
    assert_eq!(clear_string.is_encrypted(), false);

    // encrypt strings with or without padding (non trivial and trivial)
    let padding = 2;
    let encrypted_string = client_key.encrypt_str("Hello", padding);
    let encrypted_string_2 = client_key.encrypt_fhe_string(&clear_string, padding);
    let encrypted_string_trivial = server_key.trivial_encrypt_fhe_string(&clear_string, 0);

    assert_eq!(encrypted_string.is_clear(), false);
    assert_eq!(encrypted_string.is_encrypted(), true);

    assert_eq!(encrypted_string.is_padded(), true);
    assert_eq!(encrypted_string_trivial.is_padded(), false);

    // decrypt
    let decrypted = client_key.decrypt_fhe_string(&encrypted_string);

    assert_eq!(decrypted.is_clear(), true);
    assert_eq!(decrypted.is_encrypted(), false);

    // check that empty characters were removed
    assert_eq!( clear_string.to_string(), decrypted.to_string() );



    // // Repeat the encrypted string, which will cause some empty characters to stay in the middle of the result
    let repeated = server_key.repeat(&encrypted_string, 3);

    // The result can be decrypted normally:
    println!("repeated : {}", client_key.decrypt_fhe_string(&repeated).to_string() );

    // But it cannot be reused in some functions, for instance contains:
    assert_eq!(repeated.is_reusable(), false);
    // server_key.contains(&repeated, &encrypted_string); // this would throw !



    // Now repeat the string but with the reusable version of the function, which takes more time:
    let repeated_reusable = server_key.repeat_reusable(&encrypted_string, 3);

    // this also works, but is longer in generall (same for repeat):
    let repeated_reusable_2 = server_key.make_reusable(&repeated);

    // The result can still be decrypted normally:
    println!("repeated_reusable : {}", client_key.decrypt_fhe_string(& repeated_reusable).to_string() );

    // It can be reused in all functions, for instance contains:
    assert_eq!(repeated_reusable.is_reusable(), true);
    assert_eq!(repeated_reusable_2.is_reusable(), true);
    let result = server_key.contains(&repeated_reusable, &encrypted_string);

    assert!( client_key.decrypt_bool(&result) );
    println!("All Ok.");
}