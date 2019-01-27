use std::{ io::{ Read, Write }, process::{ Command, Stdio } };


/// The keys used for the predefined ciphertexts
const KEYS: [&str; 8] = [
	"3756cc36-770620df-aa453631-6dcae688-80f5dafd-804a8739-2984a520-51eef1af",
	"b0c76492-b09fada6-4229bb2c-d710f42d-80054860-d8fcaf3e-4805a1df-e8ff122a",
	"78bd40ec-014338a7-ef9ccf7a-7de9a917-057d8a10-a5ab4ebb-16289c2d-88d120d5",
	"9d700468-594c4426-efc177ef-f480373d-c1d724a5-092c64e5-ad78b4db-7de807a5",
	"81f514b1-1745a91d-04b90403-f6f5dba9-86d2de8b-6b8190ef-bc74e528-5dd375b9",
	"1203d773-bb9acf3b-08f28aa0-5271b26d-939bf8df-9a795ff9-e3c1f76b-8de5da12",
	"e3051926-a33d25ae-e81dd789-c2ab505f-8ac1900f-b8280c68-e13dc629-a1c19eec",
	"8db9d378-f77f471f-9183738c-8cd776ba-59e6bce7-7bac62c1-23cff5b2-0e3cccab"
];
/// The predefined plaintexts
const PLAINTEXTS: [&[u8]; 8] = [
	include_bytes!("data.0.plaintext"), include_bytes!("data.1.plaintext"),
	include_bytes!("data.2.plaintext"), include_bytes!("data.3.plaintext"),
	include_bytes!("data.4.plaintext"), include_bytes!("data.5.plaintext"),
	include_bytes!("data.6.plaintext"), include_bytes!("data.7.plaintext")
];
/// The predefined ciphertexts
const CIPHERTEXTS: [&[u8]; 8] = [
	include_bytes!("data.0.ciphertext"), include_bytes!("data.1.ciphertext"),
	include_bytes!("data.2.ciphertext"), include_bytes!("data.3.ciphertext"),
	include_bytes!("data.4.ciphertext"), include_bytes!("data.5.ciphertext"),
	include_bytes!("data.6.ciphertext"), include_bytes!("data.7.ciphertext")
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