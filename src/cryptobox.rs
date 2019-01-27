use crate::{
	sodium_bindings::{
		randombytes_buf,
		crypto_secretbox_xchacha20poly1305_NONCEBYTES, crypto_secretbox_xchacha20poly1305_MACBYTES,
		crypto_secretbox_xchacha20poly1305_easy, crypto_secretbox_xchacha20poly1305_open_easy
	}
};


/// The header
const HEADER: &[u8; 48] = b"de.KizzyCode.Cryptobox.v1.XChaCha20Poly1305Ietf_";
/// The nonce length
const NONCE_LEN: usize = crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize;
/// The MAC size for all algorithms
const MAC_LEN: usize = crypto_secretbox_xchacha20poly1305_MACBYTES as usize;


/// Seals `data` using `key`
pub fn seal(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
	// Write header
	let mut buf = HEADER.to_vec();
	
	// Create and write the nonce
	let mut nonce = vec![0u8; NONCE_LEN];
	sodium!(nonce.as_mut_ptr(), nonce.len() => randombytes_buf);
	buf.extend_from_slice(&nonce);
	
	// Resize the buffer to hold the sealed payload
	buf.resize(HEADER.len() + NONCE_LEN + data.len() + MAC_LEN, 0x00);
	let payload_buf = &mut buf[HEADER.len() + NONCE_LEN..];
	
	// Seal the data
	let result = sodium!(
		payload_buf.as_mut_ptr(), data.as_ptr(), data.len(),
		nonce.as_ptr(), key.as_ptr()
			=> crypto_secretbox_xchacha20poly1305_easy
	);
	match result {
		0 => buf,
		_ => fail!(internal_err => "Failed to seal data")
	}
}


/// Opens `data` into `buf` using `key`
pub fn open(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
	// Validate header
	if data.len() < HEADER.len() + NONCE_LEN { fail!(data_err => "Truncated header") }
	if !data.starts_with(HEADER) { fail!(data_err => "Unsupported header") }
	
	// Get nonce nonce and data
	let nonce = &data[HEADER.len() .. HEADER.len() + NONCE_LEN];
	let data = &data[HEADER.len() + NONCE_LEN ..];
	
	// Create the buffer for the decrypted payload
	if data.len() < MAC_LEN { fail!(data_err => "Truncated stream") }
	let mut buf = vec![0u8; data.len() - MAC_LEN];
	
	// Open data
	let result = sodium!(
		buf.as_mut_ptr(), data.as_ptr(), data.len(), nonce.as_ptr(), key.as_ptr()
			=> crypto_secretbox_xchacha20poly1305_open_easy
	);
	match result {
		0 => buf,
		_ => fail!(data_err => "Failed to open data")
	}
}