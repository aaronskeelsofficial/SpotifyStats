use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use crate::modules::database::logintoken_info::LoginTokenInfo;

// Generate a random alphanumeric token
fn generate_token() -> String {
    let mut rng = OsRng; // Use a cryptographically secure RNG
    let token: String = (0..32)
        .map(|_| rng.sample(Alphanumeric)) // Secure sampling
        .map(char::from)
        .collect();
    token
}

pub fn request_generate_token_for_uuid(uuid: &String) -> String {
    let potential_logintoken_info = crate::modules::database::logintoken_info::get_logintokeninfo_from_uuid(uuid);
    if if_token_already_exists(&potential_logintoken_info) && if_token_timestamp_is_valid(&potential_logintoken_info) {
        return potential_logintoken_info.unwrap().token.unwrap();
    } else {
        let token = generate_token();
        crate::modules::database::logintoken_info::set_token_info(&token, uuid, &Utc::now().to_rfc3339().to_string()).unwrap();
        return token;
    }
}

fn if_token_already_exists(potential_logintoken_info: &Result<LoginTokenInfo, rusqlite::Error>) -> bool {
    match potential_logintoken_info {
        Ok(_) => true,
        Err(_) => false
    }
}

fn if_token_timestamp_is_valid(potential_logintoken_info: &Result<LoginTokenInfo, rusqlite::Error>) -> bool {
    match potential_logintoken_info {
        Ok(logintoken_info) => {
            let now = Utc::now();
            let last_used = DateTime::parse_from_rfc3339(&logintoken_info.last_used_timestamp.clone().unwrap()).unwrap().to_utc();
            let lifetime = Duration::minutes(20);
            if now - last_used >= lifetime {
                return false;
            } else {
                return true;
            }
        },
        Err(_) => false
    }
}

pub fn validate_and_ping_token(token: &String) -> bool {
    let potential_logintoken_info = crate::modules::database::logintoken_info::get_logintokeninfo_from_token(token);
    if if_token_already_exists(&potential_logintoken_info) && if_token_timestamp_is_valid(&potential_logintoken_info) {
        let logintoken_info = potential_logintoken_info.unwrap();
        crate::modules::database::logintoken_info::set_token_info(token, &logintoken_info.uuid.clone().unwrap(), &Utc::now().to_rfc3339().to_string()).unwrap();
        return true;
    } else {
        return false;
    }
}