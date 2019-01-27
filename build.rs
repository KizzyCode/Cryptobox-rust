extern crate pkg_config;

const LIBSODIUM_VERSION: &str = "1.0.17";

fn main() {
	// Link libsodium
	let libsodium = pkg_config::Config::new().statik(true).find("libsodium").unwrap();
	if libsodium.version != LIBSODIUM_VERSION {
		panic!("Invalid libsodium version ({}; expected {})", libsodium.version, LIBSODIUM_VERSION)
	}
	println!("cargo:rustc-link-lib=static=sodium");
}