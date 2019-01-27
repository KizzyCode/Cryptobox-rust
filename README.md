[![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)


# About Cryptobox
Cryptobox is a [KISS](https://en.wikipedia.org/wiki/KISS_principle) data en-/decryption-tool that generates a random
256bit key and hex-prints it to StdErr, seals everything from from StdIn with this random key using
[libsodium's `crypto_secretbox_xchacha20poly1305_easy`](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption)
and writes the sealed data to StdOut.

The idea is to keep the code as simple as possible so that it's easy to understand and validate it (this is also the
reason why we use [libsodium](https://libsodium.org) as backend).

Optionally Cryptobox can use [`ma_proper`](https://crates.io/crates/ma_proper) as memory allocator to ensure that the
allocated memory is overwritten before it is returned to the OS (feature `use-maproper`; disabled by default).


## Use-Case
The use-case is pretty limited – in particular, Cryptobox is __NOT__ suited for
 - large files: Cryptobox reads the _entire_ input from StdIn and writes the result to a _different_ memory location –
   this means that Cryptobox requires at least two times the input-size as memory
 - any kind of password based encryption: Cryptobox uses a new random key for each encryption and displays the raw hex
   key – it's up to you to store it somewhere safe and secure

Instead, the use-case is secure long-term encryption of small sensible data for backup purposes. E.g. you could encrypt
your GnuPG-keyring and upload it to [Pastebin.com](https://pastebin.com) – this way you only need to store 64 hex chars
in a safe and secure place instead of the entire keyring.


## Encryption
To seal a some data, pipe it to `cryptobox`' StdIn and redirect the StdOut to your target location:
```sh
cryptobox < /path/to/secret.file > /path/to/sealed.file
```

__Important: Store the displayed key somewhere safe! Without this key it's probably COMPLETELY IMPOSSIBLE to recover
your data from the sealed file.__


## Decryption
To decrypt some data, export the key as environment variable and pipe it to `cryptobox`' StdIn and redirect the StdOut
to your target location:
```sh
export CRYPTOBOX_KEY=0197ac79-e307baf7-facd0c5c-9b1b3951-990d7dd5-4cffc259-fd6ac95c-2f3b1a1c
cryptobox < /path/to/sealed.file > /path/to/secret.file
```

(Cryptobox detects your exported key automatically and switches to decryption mode – to delete the key from the
environment, use `unset CRYPTOBOX_KEY`)