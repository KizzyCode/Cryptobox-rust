use std::{
	os::raw::{ c_void, c_uchar, c_int }, io::{ Read, Write, stdout }, process::{ Command, Stdio }
};


/// A factor that determines the amount of test iterations to run
const TEST_FACTOR: usize = 24;
/// The maximum limit of the plaintext size to test
const TEST_PLAINTEXT_LIMIT: u32 = 32 * 1024 * 1024;


/// The preamble for encryption with a random key
const RANDOM_KEY_PREAMBLE: &[u8] = b"Encrypting with random key: ";
/// The preamble for decryption with an environment key
const ENV_KEY_PREAMBLE: &[u8] = b"Decrypting with environment key: ";
/// The header
const HEADER: &[u8] = b"de.KizzyCode.Cryptobox.v1.XChaCha20Poly1305Ietf_";


// Define the executable to use
#[cfg(debug_assertions)] const PROGRAM: &str = "target/debug/cryptobox";
#[cfg(not(debug_assertions))] const PROGRAM: &str = "target/release/cryptobox";


/// Generate `len` random bytes
fn random(len: usize) -> Vec<u8> {
	// Declare libsodium bindings
	extern "C" {
		fn sodium_init() -> c_int;
		
		fn randombytes_seedbytes() -> usize;
		fn randombytes_buf(buf: *mut c_void, size: usize);
		fn randombytes_buf_deterministic(buf: *mut c_void, size: usize, seed: *const c_uchar);
	}
	assert!(unsafe{ sodium_init() } >= 0);
	
	// Generate random seed
	let mut seed = vec![0u8; unsafe{ randombytes_seedbytes() }];
	unsafe{ randombytes_buf(seed.as_mut_ptr() as _, seed.len()) }
	
	// Create the random bytes
	let mut buf = vec![0u8; len];
	unsafe{ randombytes_buf_deterministic(
		buf.as_mut_ptr() as _, buf.len(),
		seed.as_ptr() as _
	) };
	
	buf
}
/// Generate a uniform random `u32` within `[0, upper_bound)`
fn random_u32(upper_bound: u32) -> u32 {
	// Declare libsodium binding and generate number
	extern "C" {
		fn sodium_init() -> c_int;
		fn randombytes_uniform(upper_bound: u32) -> u32;
	}
	assert!(unsafe{ sodium_init() } >= 0);
	unsafe{ randombytes_uniform(upper_bound) }
}


/// Read `input` to EOF
fn read_to_end(mut input: impl Read) -> Vec<u8> {
	let mut buf = Vec::new();
	let buf_len = input.read_to_end(&mut buf).unwrap();
	
	buf.truncate(buf_len);
	buf
}


/// Encrypt data
fn encrypt(data: &[u8]) -> (Vec<u8>, String) {
	// Start the command
	let mut command = Command::new(PROGRAM)
		.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
		.env_clear()
		.spawn().unwrap();
	
	// Write all data
	command.stdin.take().unwrap().write_all(data).unwrap();
	
	// Read StdOE and wait until exit
	let stdout = read_to_end(command.stdout.take().unwrap());
	let stderr = read_to_end(command.stderr.take().unwrap());
	assert!(command.wait().unwrap().success());
	
	// Extract key
	let key = match stderr.starts_with(RANDOM_KEY_PREAMBLE) {
		true => String::from_utf8_lossy(&stderr[RANDOM_KEY_PREAMBLE.len()..]).trim().to_string(),
		false => panic!("No key on StdErr")
	};
	
	(stdout, key)
}


/// Decrypt data
fn decrypt(data: &[u8], key: &str) -> Result<Vec<u8>, String> {
	// Start the command
	let mut command = Command::new(PROGRAM)
		.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
		.env_clear().env("CRYPTOBOX_KEY", key)
		.spawn().unwrap();
	
	// Write all data
	command.stdin.take().unwrap().write_all(data).unwrap();
	
	// Read StdOE and wait until exit
	let stdout = read_to_end(command.stdout.take().unwrap());
	let stderr = read_to_end(command.stderr.take().unwrap());
	if !command.wait().unwrap().success() {
		return Err(String::from_utf8_lossy(&stderr).to_string())
	}
	
	// Validate key
	let env_key = match stderr.starts_with(ENV_KEY_PREAMBLE) {
		true => String::from_utf8_lossy(&stderr[ENV_KEY_PREAMBLE.len()..]).trim().to_string(),
		false => panic!("No key on StdErr")
	};
	assert_eq!(key, env_key);
	
	Ok(stdout)
}


/// Test stub to test `plaintext -> ciphertext -> plaintext` cycles
fn test_encrypt_decrypt() {
	// Generate random plaintext
	let len = random_u32(TEST_PLAINTEXT_LIMIT) as usize;
	let data = random(len);
	
	// Encrypt and decrypt data
	let (ciphertext, key) = encrypt(&data);
	let plaintext = decrypt(&ciphertext, &key).unwrap();
	
	// Validate header and plaintext
	assert!(ciphertext.starts_with(HEADER));
	assert_eq!(plaintext, data);
	
	// Print progress dots
	print!("🍺"); stdout().flush().unwrap();
}


/// Test stub to test `plaintext -> ciphertext -> invalid-text -> error` cycles
fn test_error() {
	// Generate random plaintext
	let len = random_u32(TEST_PLAINTEXT_LIMIT) as usize;
	let data = random(len);
	
	// Encrypt data
	let (mut ciphertext, key) = encrypt(&data);
	
	// Introduce random fault
	let fault_index = random_u32(ciphertext.len() as u32) as usize;
	ciphertext[fault_index] ^= 0b0000_0100;
	
	// Decrypt data and validate the output
	let err = match fault_index < HEADER.len() {
		true => "Fatal data error @src/cryptobox.rs:49: Unsupported header",
		false => "Fatal data error @src/cryptobox.rs:66: Failed to open data"
	};
	assert!(decrypt(&ciphertext, &key).unwrap_err().trim().ends_with(err));
	
	// Print progress dots
	print!("🍻"); stdout().flush().unwrap();
}


// El-cheapo multithreading for tests
#[test] fn test_ok_0() {
	(0..TEST_FACTOR).for_each(|_| test_encrypt_decrypt());
}
#[test] fn test_ok_1() {
	(0..TEST_FACTOR).for_each(|_| test_encrypt_decrypt());
}
#[test] fn test_ok_2() {
	(0..TEST_FACTOR).for_each(|_| test_encrypt_decrypt());
}
#[test] fn test_ok_3() {
	(0..TEST_FACTOR).for_each(|_| test_encrypt_decrypt());
}


// El-cheapo multithreading for failing tests
#[test] fn test_err_0() {
	(0..TEST_FACTOR).for_each(|_| test_error());
}
#[test] fn test_err_1() {
	(0..TEST_FACTOR).for_each(|_| test_error());
}
#[test] fn test_err_2() {
	(0..TEST_FACTOR).for_each(|_| test_error());
}
#[test] fn test_err_3() {
	(0..TEST_FACTOR).for_each(|_| test_error());
}