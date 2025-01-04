pub mod loginnonce;
pub mod logintoken;

use std::env;

use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};

use base64::{prelude::BASE64_STANDARD, Engine};

pub fn decrypt_login(encrypted_password: &str) -> String {
    let base64_private_key = env::var("LOGIN_RSA_PRIVATE_KEY").unwrap();
    let decoded_private_key = String::from_utf8(BASE64_STANDARD.decode(base64_private_key).unwrap()).unwrap();
    // println!("Decoded Private Key:\n{}", &decoded_private_key);
    // println!("Encrypted Password: {}", &encrypted_password);
    let private_key = RsaPrivateKey::from_pkcs8_pem(&decoded_private_key).unwrap();
    let base64_decoded_encrypted_password = BASE64_STANDARD.decode(encrypted_password).unwrap();
    let decrypted_password_vec = private_key.decrypt(rsa::pkcs1v15::Pkcs1v15Encrypt, &base64_decoded_encrypted_password).unwrap();
    let decrypted_password = String::from_utf8(decrypted_password_vec).unwrap();
    // println!("Decrypted Password: {}", decrypted_password);
    let nonced_password = decrypted_password;
    return nonced_password;
}