use std::{collections::HashMap, sync::Mutex, time::Instant};
use rand::Rng;
use tokio::time::{sleep, Duration as TokioDuration};
use lazy_static::lazy_static;

lazy_static! {
    static ref NONCES_LOGIN: Mutex<HashMap<String, Instant>> = Mutex::new(HashMap::new());
}

const NONCE_LIFETIME: TokioDuration = TokioDuration::from_secs(10);


// Generate a random alphanumeric nonce
pub fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let nonce: String = (0..32)
        .map(|_| rng.sample(rand::distributions::Alphanumeric))
        .map(char::from)
        .collect();
    add_nonce(nonce.clone());
    return nonce;
}

// Add a nonce with timestamp to the global map
pub fn add_nonce(nonce: String) {
    let mut nonces = NONCES_LOGIN.lock().unwrap();
    let timestamp = Instant::now(); // Record the current timestamp
    nonces.insert(nonce, timestamp);
}

// Check if a nonce exists in the map
pub fn is_nonce_valid(nonce: &str) -> bool {
    let nonces = NONCES_LOGIN.lock().unwrap();
    nonces.contains_key(nonce)
}

// Remove a nonce from the global map
pub fn remove_nonce(nonce: &str) {
    let mut nonces = NONCES_LOGIN.lock().unwrap();
    nonces.remove(nonce);
}

// Cleanup expired nonces based on their timestamp
pub async fn cleanup_nonces() {
    loop {
        sleep(NONCE_LIFETIME).await;
        let now = Instant::now();
        let mut nonces = NONCES_LOGIN.lock().unwrap();
        // Iterate through the nonces and remove those that have expired
        nonces.retain(|_, timestamp| now.duration_since(*timestamp) < NONCE_LIFETIME);
        println!("Cleanup complete. Current active nonces: {}", nonces.len());
    }
}