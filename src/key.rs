use crate::sodium_bindings::randombytes_buf;
use std::env;


/// The name of the environment variable containing the hex-encoded key
const KEY_ENV_VAR_NAME: &str = "CRYPTOBOX_KEY";
/// The key length for all ciphers
const KEY_LEN: usize = 32;


/// Print a key
fn print_key(desc: &str, key: &[u8]) {
	eprint!("{}: ", desc);
	
	key.iter().enumerate().for_each(|(i, b)| {
		if i != 0 && i % 4 == 0 { eprint!("-") }
		eprint!("{:02x}", *b);
	});
	
	eprintln!()
}


/// Gets the key from the environment variable
fn from_env(key_hex: String) -> Vec<u8> {
	// Filter non-hex-chars and parse nibbles
	let parsed: Vec<u8> = key_hex.bytes().filter_map(|b| match b {
		b @ b'0'...b'9' => Some(b - b'0'),
		b @ b'a'...b'f' => Some((b + 10) - b'a'),
		b @ b'A'...b'F' => Some((b + 10) - b'A'),
		_ => None
	}).collect();
	
	// Validate the key length and combine the nibbles
	if parsed.len() % 2 != 0 { fail!(api_err => "Invalid key (invalid hex length)") }
	if parsed.len() / 2 != KEY_LEN { fail!(api_err => "Invalid key (invalid key length)") }
	
	// Combine the nibbles, print and return the key
	let key: Vec<u8> = parsed.chunks(2).map(|s| s[0] << 4 | s[1]).collect();
	print_key("Decrypting with environment key", &key);
	key
}


/// Generates a new random key
fn from_random() -> Vec<u8> {
	// Generate random key
	let mut key = vec![0u8; KEY_LEN];
	sodium!(key.as_mut_ptr(), key.len() => randombytes_buf);
	
	// Print and return key
	print_key("Encrypting with random key", &key);
	key
}


/// A key representation
pub enum Key {
	/// A key from the environment
	Env(Vec<u8>),
	/// A randomly generated key
	Random(Vec<u8>)
}
impl Key {
	/// Gets the key from te environment or generates a random one if none is set
	pub fn get() -> Self {
		match env::var(KEY_ENV_VAR_NAME) {
			Ok(key_hex) => Key::Env(from_env(key_hex)),
			Err(_) => Key::Random(from_random())
		}
	}
}