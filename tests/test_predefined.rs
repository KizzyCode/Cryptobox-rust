use std::{ io::{ Read, Write }, process::{ Command, Stdio } };


/// The keys used for the predefined ciphertexts
const KEYS: [&str; 2] = [
	"3756cc36-770620df-aa453631-6dcae688-80f5dafd-804a8739-2984a520-51eef1af",
	"875b78a0-46265b48-7e81e5f0-51c8f09d-ac431aa5-6e76d2b6-643abc0e-4d783b27"
];
/// The predefined plaintexts
const PLAINTEXTS: [&[u8]; 2] = [
	include_bytes!("data.0.plaintext"), include_bytes!("data.1.plaintext")
];
/// The predefined ciphertexts
const CIPHERTEXTS: [&[u8]; 2] = [
	include_bytes!("data.0.ciphertext"), include_bytes!("data.1.ciphertext")
];


/// The preamble for decryption with an environment key
const ENV_KEY_PREAMBLE: &[u8] = b"Decrypting with environment key: ";


// Define the executable to use
#[cfg(debug_assertions)] const PROGRAM: &str = "target/debug/cryptobox";
#[cfg(not(debug_assertions))] const PROGRAM: &str = "target/release/cryptobox";


/// Read `input` to EOF
fn read_to_end(mut input: impl Read) -> Vec<u8> {
	let mut buf = Vec::new();
	let buf_len = input.read_to_end(&mut buf).unwrap();
	
	buf.truncate(buf_len);
	buf
}


/// Decrypt data
fn decrypt(index: usize) -> Result<(), String> {
	// Start the command
	let mut command = Command::new(PROGRAM)
		.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
		.env_clear().env("CRYPTOBOX_KEY", KEYS[index])
		.spawn().unwrap();
	
	// Write all data
	command.stdin.take().unwrap().write_all(CIPHERTEXTS[index]).unwrap();
	
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
	assert_eq!(KEYS[index], env_key);
	
	// Validate plaintext
	assert_eq!(stdout, PLAINTEXTS[index]);
	Ok(())
}


#[test] fn test() {
	(0..KEYS.len()).for_each(|i| decrypt(i).unwrap());
}