# fhe-string
fhe-string bounty

## Presentation

See `src/readme_tutorial.rs`

### **ClientKey** and **ServerKey**
**ClientKey** and **ServerKey** are wrapper classes for **gen_keys_radix** objects. Here is how to initiliaze them:

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

use crate::client_key::ClientKey;
use crate::server_key::ServerKey;

// number of blocks required to encode an ASCII char (8 bits)
pub static NUMBER_OF_BLOCKS: usize = 4;

// Generation of the client/server keys, using the default parameters and 4 blocks for u8:
let (integer_client_key, integer_server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUMBER_OF_BLOCKS);

// Wrap client/server keys
let client_key = ClientKey::new(integer_client_key);
let server_key = ServerKey::new(integer_server_key);
```

### **FheString**

**FheString** objects can hold clear or encrypted ASCII characters.  

Encrypted strings may be padded with encrypted `'\0'` empty characters. Any `'\0'` empty character inside a **FheString** will be removed at decryption. A flag `is_padded()` tells wether a **FheString** is padded or not. Most of algorithms have different behaviors for padded and non padded strings, and are faster without padding.  
  
Here is how to create clear and encrypted **FheString** objects, and how to decrypt/convert them back to strings:

```rust
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
```

#### Reusability of encrypted **FheString** objects
Some algorithms may leave empty characters at the beggining or in the middle of a **FheString**, and not only at the end. This is not an issue if they are not reused as inputs to other FheString algorithms. In this case, the **FheString** has a flag `is_reusable()` that will return `false`. Inputting this non reusable **FheString** to other algorithms that require reusable **FheStrings** will throw an error.  

```rust
// Repeat the encrypted string, which will cause some empty characters to stay in the middle of the result
let repeated = server_key.repeat(&encrypted_string, 3);

// The result can be decrypted normally:
println!("repeated : {}", client_key.decrypt_fhe_string(&repeated).to_string() );

// But it cannot be reused in some functions, for instance contains:
assert_eq!(repeated.is_reusable(), false);
// server_key.contains(&repeated, &encrypted_string); // this would throw !
```

If one wants to reuse a **FheString** as an input to another algorithm requiring a reusable **FheString**, one needs to use the `_reusable` version of the functions.  
It is also possible to use `server_key.make_reusable` of a non reusable **FheString**, but it is generally slower thant using the `_reusable` version of the function in the first place. Indeed, faster algorithms than `server_key.make_reusable`, adapted to the particular case of the function `_reusable`, are used inside.

```rust
// Now repeat the string but with the reusable version of the function, which takes more time:
let repeated_reusable = server_key.repeat_reusable(&encrypted_string, 3);

// The result can still be decrypted normally:
println!("repeated_reusable : {}", client_key.decrypt_fhe_string(& repeated_reusable).to_string() );

// this also works, but is longer in generall (same for repeat):
let repeated_reusable_2 = server_key.make_reusable(&repeated);

// It can be reused in all functions, for instance contains:
assert_eq!(repeated_reusable.is_reusable(), true);
assert_eq!(repeated_reusable_2.is_reusable(), true);
let result = server_key.contains(&repeated_reusable, &encrypted_string);

assert!( client_key.decrypt_bool(&result) );

println!("All Ok.");
```

## Build
```bash
cargo build --release
```

## Run
Create a link with `ln -s ./target/release/fhe-str fhe-str` then run `./fhe-str` with the following parameters:
- `--help` or `-h` for help
- `--string` the string
- `--padding-string` the padding of the string
- `--pattern` the pattern
- `--padding-pattern` the padding of the pattern
- `--pattern-to` the "to" pattern for replace functions
- `--padding-to` the padding of the "to" pattern
- `--n` a number n for functions like splitn or repeat
- `--module` the name of a specific module (put nothing or "all" for all of them):
	- mod
	- partial-ordering
	- case
	- contains
	- find
	- trim
	- strip
    - split
    - replace
    - repeat	

For instance:
```bash
./fhe-str --string "a string" --padding-string 10 --pattern "a pattern" --padding-pattern 2 --pattern-to "another pattern" --padding-to 0 --n 2 --module "a module"
```

## Create documentation
Without private items:
```bash 
cargo doc --no-deps
```

With private items:
```bash 
cargo doc --no-deps --document-private-items
```


## Test special cases
You can run your own tests or use the ones below to make sure everything works.

#### Tests for all modules
```bash
# empty no padding
./fhe-str --string "" --padding-string 0 --pattern "" --padding-pattern 0
./fhe-str --string "" --padding-string 0 --pattern "a" --padding-pattern 0
./fhe-str --string "a" --padding-string 0 --pattern "" --padding-pattern 0

# empty with padding
./fhe-str --string "" --padding-string 1 --pattern "" --padding-pattern 0
./fhe-str --string "" --padding-string 0 --pattern "" --padding-pattern 1
./fhe-str --string "" --padding-string 1 --pattern "" --padding-pattern 1

# not empty no padding
./fhe-str --string "aBcD" --padding-string 0 --pattern "aB" --padding-pattern 0

# not empty no padding and string is shorter than pattern
./fhe-str --string "aB" --padding-string 0 --pattern "aBcD" --padding-pattern 0

# not empty padding
./fhe-str --string "aBcD" --padding-string 0 --pattern "aB" --padding-pattern 4
./fhe-str --string "aBcD" --padding-string 4 --pattern "aB" --padding-pattern 0
./fhe-str --string "aBcD" --padding-string 4 --pattern "aB" --padding-pattern 4

# not empty padding and string is shorter than pattern
./fhe-str --string "aB" --padding-string 0 --pattern "aBcD" --padding-pattern 4
./fhe-str --string "aB" --padding-string 4 --pattern "aBcD" --padding-pattern 0
./fhe-str --string "aB" --padding-string 4 --pattern "aBcD" --padding-pattern 4
```

#### Tests for `mod.rs` : eq and ne (is_empty already tested above)
```bash
./fhe-str --string "aa" --padding-string 0 --pattern "aa" --padding-pattern 0 --mod mod
./fhe-str --string "aa" --padding-string 2 --pattern "aa" --padding-pattern 0 --mod mod
./fhe-str --string "aa" --padding-string 0 --pattern "aa" --padding-pattern 2 --mod mod
./fhe-str --string "aa" --padding-string 2 --pattern "aa" --padding-pattern 2 --mod mod
./fhe-str --string "aa" --padding-string 0 --pattern "ab" --padding-pattern 0 --mod mod
```

#### Tests for partial ordering: le, lt, ge, gt
```bash
./fhe-str --string "aa" --padding-string 0 --pattern "ab" --padding-pattern 0 --mod partial-ordering
./fhe-str --string "aa" --padding-string 2 --pattern "ab" --padding-pattern 0 --mod partial-ordering
./fhe-str --string "aa" --padding-string 0 --pattern "ab" --padding-pattern 2 --mod partial-ordering
./fhe-str --string "aa" --padding-string 2 --pattern "ab" --padding-pattern 2 --mod partial-ordering
./fhe-str --string "aa" --padding-string 0 --pattern "aaa" --padding-pattern 0 --mod partial-ordering
./fhe-str --string "aaaaaa" --padding-string 0 --pattern "aabaaa" --padding-pattern 0 --mod partial-ordering
./fhe-str --string "aa" --padding-string 0 --pattern "aA" --padding-pattern 0 --mod partial-ordering
```

#### Tests case: to_lower_case, to_upper_case, eq_ignore_case
```bash
./fhe-str --string "aBcD" --padding-string 0 --pattern "abcd" --padding-pattern 0 --mod case
./fhe-str --string "aBcD" --padding-string 2 --pattern "abcd" --padding-pattern 0 --mod case
./fhe-str --string "aBcD" --padding-string 0 --pattern "abcd" --padding-pattern 2 --mod case
./fhe-str --string "aBcD" --padding-string 2 --pattern "abcd" --padding-pattern 2 --mod case
```

#### Tests contains, starts with, ends with
```bash
# no padding
./fhe-str --string "abcdef" --padding-string 0 --pattern "abc" --padding-pattern 0 --mod contains
./fhe-str --string "abcdef" --padding-string 0 --pattern "bcd" --padding-pattern 0 --mod contains
./fhe-str --string "abcdef" --padding-string 0 --pattern "def" --padding-pattern 0 --mod contains

# padding pattern
./fhe-str --string "abcdef" --padding-string 0 --pattern "abc" --padding-pattern 2 --mod contains
./fhe-str --string "abcdef" --padding-string 0 --pattern "bcd" --padding-pattern 2 --mod contains
./fhe-str --string "abcdef" --padding-string 0 --pattern "def" --padding-pattern 2 --mod contains

# padding string
./fhe-str --string "abcdef" --padding-string 2 --pattern "abc" --padding-pattern 0 --mod contains
./fhe-str --string "abcdef" --padding-string 2 --pattern "bcd" --padding-pattern 0 --mod contains
./fhe-str --string "abcdef" --padding-string 2 --pattern "def" --padding-pattern 0 --mod contains
```

#### Tests find and rfind
```bash
# no padding
./fhe-str --string "abcdef" --padding-string 0 --pattern "abc" --padding-pattern 0 --mod find
./fhe-str --string "abcdef" --padding-string 0 --pattern "cde" --padding-pattern 0 --mod find

# padding pattern
./fhe-str --string "abcdef" --padding-string 0 --pattern "abc" --padding-pattern 2 --mod find
./fhe-str --string "abcdef" --padding-string 0 --pattern "cde" --padding-pattern 2 --mod find

# padding string
./fhe-str --string "abcdef" --padding-string 2 --pattern "abc" --padding-pattern 0 --mod find
./fhe-str --string "abcdef" --padding-string 2 --pattern "cde" --padding-pattern 0 --mod find

# both padding
./fhe-str --string "abcdef" --padding-string 2 --pattern "abc" --padding-pattern 2 --mod find
./fhe-str --string "abcdef" --padding-string 2 --pattern "cde" --padding-pattern 2 --mod find
```

#### Tests trim, trim_start, trim_end
```bash
# no padding
./fhe-str --string "  abc  " --padding-string 0 --mod trim

# padding
./fhe-str --string "  abc  " --padding-string 2 --mod trim
```

#### Tests strip_prefix, strip_suffix
```bash
./fhe-str --string "abcdefabc" --padding-string 0 --pattern "abc" --padding-pattern 0 --mod strip
./fhe-str --string "abcdefabc" --padding-string 2 --pattern "abc" --padding-pattern 0 --mod strip
./fhe-str --string "abcdefabc" --padding-string 0 --pattern "abc" --padding-pattern 2 --mod strip
./fhe-str --string "abcdefabc" --padding-string 2 --pattern "abc" --padding-pattern 2 --mod strip
```

#### Tests for split and related functions
```bash
# regular pattern:
./fhe-str --string "a:bc:d:" --padding-string 2 --pattern ":" --padding-pattern 0 --module split
./fhe-str --string "a:bc:d:" --padding-string 0 --pattern ":" --padding-pattern 2 --module split

# overlapping patterns:
./fhe-str --string "aaaaaaa" --padding-string 0 --pattern "aa" --padding-pattern 0 --module split
./fhe-str --string "aaaaaaa" --padding-string 0 --pattern "aa" --padding-pattern 2 --module split
./fhe-str --string "abcabcabc" --padding-string 0 --pattern "abc" --padding-pattern 0 --module split
./fhe-str --string "abcabcabc" --padding-string 0 --pattern "abc" --padding-pattern 2 --module split
./fhe-str --string "abababababa" --padding-string 0 --pattern "abab" --padding-pattern 0 --module split
./fhe-str --string "abababababa" --padding-string 0 --pattern "abab" --padding-pattern 2 --module split

# non padded pattern that is longer that string (trivial)
./fhe-str --string "a" --padding-string 0 --pattern "aa" --padding-pattern 0 --module split

# split with empty pattern (non padded and padded)
./fhe-str --string "abc" --padding-string 2 --pattern "" --padding-pattern 0 --module split
./fhe-str --string "abc" --padding-string 2 --pattern "" --padding-pattern 2 --module split

# split with empty inputs and different n
./fhe-str --string "" --padding-string 0 --pattern "" --padding-pattern 0 --n 0 --module --split
./fhe-str --string "" --padding-string 0 --pattern "" --padding-pattern 0 --n 1 --module --split
./fhe-str --string "" --padding-string 0 --pattern "" --padding-pattern 0 --n 2 --module --split
```

#### Tests for replace and replacen
```bash
# Replaceand replacen regular patterns:
./fhe-str --string "a:bc:d:ef" --padding-string 2 --pattern ":" --padding-pattern 0 --pattern_to "|" --padding-to 0 --n 2 --module replace
./fhe-str --string "a:bc:d:ef" --padding-string 0 --pattern ":" --padding-pattern 2 --pattern_to "|"  --padding-to 0 --n 2 --module replace
./fhe-str --string "I love cats and cat love me" --padding-string 2 --pattern "cat" --padding-pattern 0 --pattern_to "dog" --padding-to 0 --n 1 --module replace

# Replace, overlapping patterns:
./fhe-str --string "aaaaaaa" --padding-string 0 --pattern "aa" --padding-pattern 0 --pattern_to "hi" --padding-to 0 --module replace
./fhe-str --string "abcabcabc" --padding-string 0 --pattern "abc" --padding-pattern 0 --pattern_to "hey" --padding-to 0 --module replace
./fhe-str --string "abababababa" --padding-string 0 --pattern "abab" --padding-pattern 0 --pattern_to "yeah" --padding-to 0 --module replace

# Replace pattern with a "to" pattern of longer size (most greedy version of the algorithm)
./fhe-str --string "a:bc:d:ef" --padding-string 2 --pattern ":" --padding-pattern 0 --pattern_to "||" --padding-to 0 --module replace
# Replace pattern with a padded "from" pattern (most greedy version of the algorithm)
./fhe-str --string "a:bc:d:ef" --padding-string 2 --pattern ":" --padding-pattern 1 --pattern_to "|" --padding-to 0 --module replace

# non padded pattern that is longer that string (trivial)
./fhe-str --string "a" --padding-string 0 --pattern "aa" --padding-pattern 0 --module replace

# from pattern is empty no padding
./fhe-str --string "a:bc:d:ef" --padding-string 2 --pattern "" --padding-pattern 0 --pattern_to "|" --padding-to 0 --n 2 --module replace

# from pattern is empty with padding
./fhe-str --string "a:bc:d:ef" --padding-string 2 --pattern "" --padding-pattern 2 --pattern_to "|" --padding-to 0 --n 2 --module replace
```

#### Tests for repeat
```bash
# Regular repeat
./fhe-str --string "abc" --padding-string 0 --n 3 --module repeat
./fhe-str --string "abc" --padding-string 2 --n 3 --module repeat
# Repeat 0 times
./fhe-str --string "abc" --padding-string 2 --n 0 --module repeat
# Repeat 1 time
./fhe-str --string "abc" --padding-string 2 --n 1 --module repeat
# Repeat an empty string
./fhe-str --string "" --padding-string 0 --n 3 --module repeat
```

## Features
- The crates uses the less cloning as possible.
- Parallelization is used whenever possible with `rayon`, often with nested parallelization.
- All algorithm are generic, whhich means they should work for any particular cases (encrypted or not, padded or not, empty or not, etc.).

## Dev
Todo: 
- Use of `BooleanBlock` instead of 1 block `RadixCipherText`, in outputs of functions, and everywhere for performance ?
- allow pattern to be a matching function or an array or FheStrings (the array is done for `split_general` which accepts `&[&FheString]` for patterns).
- warn the user of the speed of the different sub-algorithms in each functions so they know if they should take out padding or encryption for some inputs ?
