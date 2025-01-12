use std::fs::File;
use base64::prelude::*;
use std::io::Write;
use rand::rngs::OsRng;
use rsa::{pkcs8::{EncodePrivateKey, EncodePublicKey}, RsaPrivateKey, RsaPublicKey};

pub mod modules;

fn main() {
    println!("Launched");
    // generate_pubpriv_keys();

    //Load Environment Variables
    dotenv::from_path("./assets/.env").unwrap();

    // println!("{}", env::var("LOGIN_RSA_PUBLIC_KEY").unwrap());
    // for (var, var2) in env::vars() {
    //     println!("- \n{}\n{}", var, var2);
    // }

    //Initialize database stuff
    crate::modules::database::first_init_if_necessary();

    // Spawn a separate thread for the web server
    let webserver_thread = std::thread::spawn(|| {
        modules::webserver::main();
    });
    // Spawn a separate thread for the scraper
    let _timedscraper_thread = std::thread::spawn(|| {
        modules::scraper::main();
    });

    // Other tasks can run in the main thread here

    // Wait for the web server thread to finish
    webserver_thread.join().unwrap();
    // // Wait for the scraper thread to finish
    // timedscraper_thread.join().unwrap();
    println!("Main thread has finished.");
}

fn _generate_pubpriv_keys() {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    // Serialize the private key to PEM format
    // let zerobullshit = private_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let zerobullshit = private_key.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
    let private_key_pem = zerobullshit.as_str().to_string();
    let private_key_base64 = BASE64_STANDARD.encode(&private_key_pem);

    // Serialize the public key to PEM format
    let public_key_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let public_key_base64 = BASE64_STANDARD.encode(&public_key_pem);

    // Save both keys (private and public) to a .env file
    let mut file = File::create(".env2").expect("failed to create .env file");
    writeln!(file, "LOGIN_RSA_PRIVATE_KEY=\"{}\"", &private_key_base64).expect("failed to write private key to .env");
    writeln!(file, "LOGIN_RSA_PUBLIC_KEY=\"{}\"", &public_key_base64).expect("failed to write public key to .env");
    writeln!(file, "\nLOGIN_RSA_PRIVATE_KEY_PEM=\"{}\"", &private_key_pem).expect("failed to write private key to .env");
    writeln!(file, "LOGIN_RSA_PUBLIC_KEY_PEM=\"{}\"", &public_key_pem).expect("failed to write public key to .env");

    println!("Private and Public keys saved to .env file!");
}