// This is a high-level implementation of the Diffie-Hellman key exchange protocol where alice and Bob generate a secret key used for secure communication.
// The program works as follows:
// 1. Alice gets a random number and generates a shared key using the shared base amd modulus
// 2. The shared key generated is sent to Bob.
// Bob processes Alice's shared key - aliceSharedKey, using his private key - bobRandomKey (i.e. aliceSharedKey ^ bobRandomKey mod PRIMEMOD) and creates a secret key
// 3. Bob then gets a random number and generates a shared key using the shared base amd modulus
// 4. Bob sends his generated shared key generated to Alice.
// Alice processes Bob's shared key, bobSharedKey, using her private key, aliceRandomKey (i.e. bobSharedKey ^ aliceRandomKey mod PRIMEMOD) and creates a secret key
// 5. Alice encrypts some data using her secret key and sends it to Bob
// 6. Bob receives the encrypted data and decrypts it with his own secret
// 7. Bob encrypts some data using his secret key and sends it to Alice
// 8. Alice receives the encrypted data and decrypts it with her own secret

use num_bigint::BigUint;
use rand::Rng;
use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;

type Aes128Ecb = Ecb<Aes128, Pkcs7>;

// The values for the expression to be used i.e. BASE mod PRIMEMOD. It is advisable to use a large primenumber for primemod for more security
const BASE: u32 = 5;
const PRIMEMOD: u32 = 57;

// Generates a random 128-bit key which will be the private keys for the parties involved. A 128-bit key means 10 rounds of AES
fn generate_random_key() -> BigUint {
    let mut rng = rand::thread_rng();
    BigUint::from(rng.gen::<u128>())
}
// Convert our BigUint secret key into a 16-byte array suitable for AES-128.
fn generate_secret_key_spec(secret_key: &BigUint) -> [u8; 16] {
    let key_bytes = secret_key.to_bytes_le();
    let mut valid_key_bytes = [0u8; 16];
    for (i, &byte) in key_bytes.iter().enumerate().take(16) {
        valid_key_bytes[i] = byte;
    }
    valid_key_bytes
}

// Encrypt the given plain text using AES-128 with the provided secret key.
fn encrypt_data(plain_text: &str, secret_key: &BigUint) -> Vec<u8> {
    let key = generate_secret_key_spec(secret_key);
    let cipher = Aes128Ecb::new_from_slices(&key, Default::default()).unwrap();
    cipher.encrypt_vec(plain_text.as_bytes())
}

// Decrypt the given encrypted data using AES-128 with the provided secret key.
fn decrypt_data(encrypted_data: &[u8], secret_key: &BigUint) -> String {
    let key = generate_secret_key_spec(secret_key);
    let cipher = Aes128Ecb::new_from_slices(&key, Default::default()).unwrap();
    let decrypted_data = cipher.decrypt_vec(encrypted_data).unwrap();
    String::from_utf8(decrypted_data).unwrap()
}

fn main() {
    // 1. Alice gets a random number and generates a shared key using the shared base amd modulus
    let alice_random_key = generate_random_key();
    println!("Alice's private key is: {}", alice_random_key);
    let alice_shared_key = BigUint::from(BASE).modpow(&alice_random_key, &BigUint::from(PRIMEMOD));
    println!("Alice's shared key that has been generated is: {}", alice_shared_key);

    // 2. The shared key generated is sent to Bob.
    // Bob processes Alice's shared key, aliceSharedKey, using his private key, bobRandomKey (i.e. aliceSharedKey ^ bobRandomKey mod PRIMEMOD) and creates a secret key
    let bob_random_key = generate_random_key();
    println!("Bob private key is: {}", bob_random_key);
    let bob_shared_key = BigUint::from(BASE).modpow(&bob_random_key, &BigUint::from(PRIMEMOD));
    println!("Bob's shared key that has been generated is: {}", bob_shared_key);
    let bob_secret_key = alice_shared_key.modpow(&bob_random_key, &BigUint::from(PRIMEMOD));
    println!("Bob has generated the secret key as: {}", bob_secret_key);

    // 3. Bob then gets a random number and generates a shared key using the shared base amd modulus
    // 4. Bob sends his generated shared key generated to Alice.
    // Alice processes Bob's shared key, bobSharedKey, using her private key, aliceRandomKey (i.e. bobSharedKey ^ aliceRandomKey mod PRIMEMOD) and creates a secret key
    let alice_secret_key = bob_shared_key.modpow(&alice_random_key, &BigUint::from(PRIMEMOD));
    println!("Alice has generated the secret key as: {}", alice_secret_key);

    // 5. Alice encrypts some data using her secret key and sends it to Bob
    let plain_text = "This is the Diffie-Hellman key exchange protocol!";
    let encrypted_data = encrypt_data(plain_text, &alice_secret_key);
    
    // 6. Bob receives the encrypted data and decrypts it with his own secret
    let decrypted_data = decrypt_data(&encrypted_data, &bob_secret_key);
    println!("Alice's decrypted data is: {}", decrypted_data);

    // 7. Bob encrypts some data using his secret key and sends it to Alice
    let plain_text2 = "This protocol is a symmetric encryption algorithm!";
    let encrypted_data2 = encrypt_data(plain_text2, &bob_secret_key);
    
    // 8. Alice receives the encrypted data and decrypts it with her own secret
    let decrypted_data2 = decrypt_data(&encrypted_data2, &alice_secret_key);
    println!("Alice's decrypted data is: {}", decrypted_data2);
}
