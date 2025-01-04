use std::{collections::HashMap, env, net::SocketAddr, path::Path};

use axum::{body, extract::{ConnectInfo, Query, Request}, http::HeaderMap, routing::{get, post}, Json, Router };
use chrono::Duration;
use serde_json::Value;
use tokio::{fs::File, io::AsyncReadExt};
use uuid::Uuid;

async fn index() -> &'static str {
    println!("Received request to /");
    "Hello, World!"
}

async fn authorize() -> axum::response::Redirect {
    println!("Received request to /authorize");
    let base_url = "https://accounts.spotify.com/authorize".to_string();
    let client_id = "?client_id=260c8b1e828041f8a6120f9eea11c15c".to_string();
    let response_type = "&response_type=code".to_string();
    let redirect_uri = "&redirect_uri=http://206.13.112.71:35565/authorizesuccess".to_string();
    let scope = "&scope=user-read-recently-played".to_string();
    let prompt = "&prompt=login".to_string(); //This forces them to login even if they already authenticated an account.
    let full_url = base_url + &client_id + &response_type + &redirect_uri + &scope + &prompt;
    println!("Redirection to Spotify");
    axum::response::Redirect::to(&full_url)
}

// struct AuthorizeSuccessQuery {
//     code: String,
// }
#[axum::debug_handler]
async fn authorizesuccess(ConnectInfo(ip): ConnectInfo<SocketAddr>, Query(query): Query<HashMap<String, String>>, headers: HeaderMap) -> axum::response::Redirect {
    println!("Received request to /authorizesuccess");
    let code = query.get("code").unwrap();
    let ip = &ip.to_string();
    let origin = headers.get("host").unwrap().to_str().unwrap();
    println!("Setting access code");
    crate::modules::database::oath_info::set_access_code(&ip, &code).unwrap();
    println!("Trading code for token");
    let _token = trade_code_for_token(origin, &ip, &code).await;
    println!("Received code and token");
    axum::response::Redirect::to("/dashboard")
}
async fn trade_code_for_token(origin: &str, ip: &String, code: &String) -> String {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &("http://".to_string() + origin + &"/authorizesuccess".to_string())),
        ("client_id", "260c8b1e828041f8a6120f9eea11c15c"),
        ("client_secret", &std::env::var("SPOTIFY_CLIENT_SECRET").unwrap())];
    let client = reqwest::Client::new();
    let res = client.post("https://accounts.spotify.com/api/token")
        .form(&params)
        .send()
        .await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    println!("{}",v);
    let token = v["access_token"].to_string();
    let token_type = v["token_type"].to_string();
    let expires_timestamp = chrono::Utc::now() + Duration::seconds(v["expires_in"].as_i64().unwrap());
    let refresh_token = v["refresh_token"].to_string();
    crate::modules::database::oath_info::set_token_info(&ip, &token, &token_type, &expires_timestamp, &refresh_token);
    v["access_token"].to_string()
}

async fn test(ConnectInfo(addr): ConnectInfo<SocketAddr>, request: Request) -> &'static str {
    println!("Received request to /test");
    println!("{}", addr);
    println!("{:?}", request);
    "test"
}

async fn signup() -> impl axum::response::IntoResponse {
    println!("Received request to /signup");
    let path = Path::new("assets/signup.html");
    // Read the file asynchronously
    let mut file = File::open(path).await.unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.unwrap();
    axum::response::Response::builder()
        .header("Content-Type", "text/html")
        .body(body::Body::from(contents))
        .unwrap()
}

// struct SignupSubmitQuery {
//     username: String,
//     hashed_password: String,
//     salt: String,
// }
async fn signupsubmit(Json(payload): Json<Value>) -> impl axum::response::IntoResponse {
    println!("Received request to /signupsubmit");
    let username = payload.get("username").unwrap().as_str().unwrap();
    // let username = query.get("username").unwrap();
    let hashed_password = payload.get("hashed_password").unwrap().as_str().unwrap();
    let salt = payload.get("salt").unwrap().as_str().unwrap();
    println!("{}\n{}\n{}", username, hashed_password, salt);
    crate::modules::database::profile_info::set_account_info(&Uuid::new_v4().to_string(), username, hashed_password, salt).unwrap();
    println!("Set account info");
    "Hello"
}

async fn login() -> impl axum::response::IntoResponse {
    println!("Received request to /login");
    let path = Path::new("assets/login.html");
    // Read the file asynchronously
    let mut file = File::open(path).await.unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.unwrap();
    axum::response::Response::builder()
        .header("Content-Type", "text/html")
        .body(body::Body::from(contents))
        .unwrap()
}

// struct LoginRequestQuery {
//     username: String,
// }
async fn loginrequest(Json(req_payload): Json<Value>) -> Json<Value> /*axum::Json<Value>*/ {
    println!("Received request to /loginrequest");
    let username = req_payload.get("username").unwrap().as_str().unwrap();
    let profile = crate::modules::database::profile_info::get_account_info(username);
    println!("{:?}", profile);
    if profile.is_err() {
        let json_value: Value = serde_json::from_str(
            r#"{
                "status": "error"
            }"#
        ).unwrap();
        return Json(json_value);
    } else {
        let string = format!(r#"{{
            "status": "success",
            "salt": "{}",
            "nonce": "{}",
            "public_key": "{}"
        }}"#, profile.unwrap().salt, crate::modules::encryption::loginnonce::generate_nonce(), env::var("LOGIN_RSA_PUBLIC_KEY").unwrap());
        let json_value: Value = serde_json::from_str(&string).unwrap();
        // let json_value: Value = serde_json::from_str("{}").unwrap();
        return Json(json_value);
    }
}

// struct LoginSubmitQuery {
//     username: String,
//     encrypted_password: String,
//     nonce: String,
// }
async fn loginsubmit(Json(req_payload): Json<Value>) -> Json<Value> {
    println!("Received request to /loginsubmit");
    //Parse Query
    let username = req_payload.get("username").unwrap().as_str().unwrap();
    let encrypted_password = req_payload.get("encrypted_password").unwrap().as_str().unwrap();
    let nonce = req_payload.get("nonce").unwrap().as_str().unwrap();
    // println!("{}\n{}\n{}", username, encrypted_password, nonce);
    //Decrypt Password
    let nonced_password = crate::modules::encryption::decrypt_login(encrypted_password);
    let hashed_password = nonced_password.replace(nonce, "");
    let profile = crate::modules::database::profile_info::get_account_info(username);
    if !crate::modules::encryption::loginnonce::is_nonce_valid(nonce) {
        let json_value: Value = serde_json::from_str(
            r#"{
                "status": "invalidnonce"
            }"#
        ).unwrap();
        return Json(json_value);
    }
    if profile.is_err() {
        let json_value: Value = serde_json::from_str(
            r#"{
                "status": "error"
            }"#
        ).unwrap();
        return Json(json_value);
    } else {
        if profile.unwrap().hashed_password.eq(&hashed_password) {
            println!("Passwords match!");
            let string = format!(r#"{{
                "status": "correctpassword"
            }}"#);
            let json_value: Value = serde_json::from_str(&string).unwrap();
            // let json_value: Value = serde_json::from_str("{}").unwrap();
            return Json(json_value);
        } else {
            println!("Passwords do not match!");
            let string = format!(r#"{{
                "status": "incorrectpassword"
            }}"#);
            let json_value: Value = serde_json::from_str(&string).unwrap();
            // let json_value: Value = serde_json::from_str("{}").unwrap();
            return Json(json_value);
        }
    }
}

pub fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // Begin nonce cleanup task
            tokio::spawn(crate::modules::encryption::loginnonce::cleanup_nonces());

            // build our application with a route
            let app = Router::new()
                .route("/", get(index))
                .route("/authorize", get(authorize))
                .route("/authorizesuccess", get(authorizesuccess))
                .route("/signup", get(signup))
                .route("/signupsubmit", post(signupsubmit))
                .route("/login", get(login))
                .route("/loginrequest", post(loginrequest))
                .route("/loginsubmit", post(loginsubmit))
                .route("/test", get(test));
                // .route("/users", post(create_user));

            let listener = tokio::net::TcpListener::bind("0.0.0.0:35565").await.unwrap();
            // axum::serve(listener, app).await.unwrap(); //Swapped for alternative below because we need client IP
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        })
}

/* Sign Up
- User visits "/signup"
- Send html file
- User enters username and password
- Client generates salt and salts password
- Client hashes salted password
- Client POST request to "/signupsubmit" with username, hashed password, and salt
- Server stores username, hashed password, and salt used (has no access to cleartext password)
 */

 /* Login
 - User visits "/login"
 - Server sends html file
 - User enters username and password
 - Client makes POST request w/ username to "/loginrequest" waiting for response with salt, nonce, and public key
 - Server responds with salt, random nonce which expires after one time use, and public key
 - Client salts password with salt
 - Client hashes salted password
 - Client appends hashed password with nonce
 - Client encrypts appended password with public key
 - Client POST request to "/loginsubmit" with username, encrypted password, nonce
 - Server checks nonce and if valid, invalidates it for future calls
 - Server decrypts password, and removes nonce from the end
 - Server checks if username and hashed password are valid
  */