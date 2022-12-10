/// Checks if `condition` evaluates to true; if not, the application terminates
macro_rules! fail {
    ($code:expr, $class:expr, $desc:expr) => {{
        use std::process::exit;
        eprintln!("Fatal {} error @{}:{}: {}\n", $class, file!(), line!(), $desc);
        exit($code);
    }};
    (api_err => $desc:expr) => {
        fail!(0x01, "user", $desc)
    };
    (data_err => $desc:expr) => {
        fail!(0x02, "data", $desc)
    };
    (internal_err => $desc:expr) => {
        fail!(0x10, "internal", $desc)
    };
}
/// Calls a libsodium function
macro_rules! sodium {
	($($arg:expr),* => $func:expr) => ({
		unsafe {
			use crate::sodium::sodium_init;
			assert!(sodium_init() >= 0, "Failed to initialize libsodium");
			($func)($($arg as _),*)
		}
	});
}

// Use MAProper if the feature is enabled
#[cfg(feature = "use-maproper")]
#[global_allocator]
static MA_PROPER: ma_proper::MAProper = ma_proper::MAProper;

// Mods
mod cryptobox;
mod key;
mod sodium;

// Includes
use key::Key;
use std::io::{stdin, stdout, Read, Write};

fn main() {
    // Get a key
    let key = Key::get();

    // Read all data from StdIn
    let mut data = Vec::new();
    match stdin().read_to_end(&mut data) {
        Ok(read) => data.truncate(read),
        Err(_) => fail!(internal_err => "Failed to read from StdIn"),
    }

    // Process the data
    let processed = match key {
        Key::Random(key) => cryptobox::seal(data, key),
        Key::Env(key) => cryptobox::open(data, key),
    };

    // Write the data to StdOut
    if stdout().write_all(&processed).is_err() {
        fail!(internal_err => "Failed to write to StdOut")
    }
}
