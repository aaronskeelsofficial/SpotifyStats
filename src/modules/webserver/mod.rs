use std::{collections::HashMap, env, net::SocketAddr, path::Path};
use axum::{body, extract::{ConnectInfo, Query, Request}, http::HeaderMap, routing::{get, post}, Json, Router };
use axum_extra::extract::CookieJar;
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Duration;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::{fs::File, io::AsyncReadExt};
use uuid::Uuid;

async fn index() -> &'static str {
    println!("Received request to /");
    "Hello, World!"
}

async fn authorize(jar: CookieJar) -> impl axum::response::IntoResponse {
    println!("Received request to /authorize");
    //Authenticate
    if jar.get("token").is_none() {
        return axum::response::Redirect::to("/login");
    }
    let logintoken = jar.get("token").unwrap().value();
    if !crate::modules::encryption::logintoken::validate_and_ping_token(&logintoken.to_string()) {
        return axum::response::Redirect::to("/login");
    }
    //
    let base_url = "https://accounts.spotify.com/authorize".to_string();
    let client_id = "?client_id=".to_string() + &env::var("SPOTIFY_CLIENT_ID").unwrap();
    let response_type = "&response_type=code".to_string();
    let redirect_uri = "&redirect_uri=http://206.13.112.71:35565/authorizesuccess".to_string();
    let scope = "&scope=user-read-recently-played".to_string();
    let prompt = "&show_dialog=false".to_string();
    // let prompt = "&show_dialog=true".to_string(); //This forces them to login even if they already authenticated an account.
    let full_url = base_url + &client_id + &response_type + &redirect_uri + &scope + &prompt;
    println!("Redirection to Spotify");
    axum::response::Redirect::to( &full_url)
}

// struct AuthorizeSuccessQuery {
//     code: String,
// }
#[axum::debug_handler]
async fn authorizesuccess(jar: CookieJar, Query(query): Query<HashMap<String, String>>, headers: HeaderMap) -> axum::response::Redirect {
    println!("Received request to /authorizesuccess");
    //Authenticate
    if jar.get("token").is_none() {
        println!("User had no token cookie. Redirecting to /login");
        return axum::response::Redirect::to("/login");
    }
    let logintoken = jar.get("token").unwrap().value();
    if !crate::modules::encryption::logintoken::validate_and_ping_token(&logintoken.to_string()) {
        println!("User had a token cookie, but the token was not valid. Redirecting to /login");
        return axum::response::Redirect::to("/login");
    }
    //
    let uuid = crate::modules::database::logintoken_info::get_logintokeninfo_from_token(&logintoken.to_string()).unwrap().uuid.unwrap();
    let code = query.get("code").unwrap();
    let origin = headers.get("host").unwrap().to_str().unwrap();
    println!("Setting access code");
    crate::modules::database::oauth_info::set_access_code(&uuid, &code).unwrap();
    println!("Trading code for token");
    let _token = trade_code_for_token(origin, &uuid, &code).await;
    println!("Received code and token");
    axum::response::Redirect::to("/dashboard")
}
async fn trade_code_for_token(origin: &str, uuid: &String, code: &String) -> String {
    // let params = [
    //     ("grant_type", "authorization_code"),
    //     ("code", &code),
    //     ("redirect_uri", &("http://".to_string() + origin + &"/authorizesuccess".to_string())),
    //     ("client_id", &env::var("SPOTIFY_CLIENT_ID").unwrap()),
    //     ("client_secret", &std::env::var("SPOTIFY_CLIENT_SECRET").unwrap())];
    // let client = reqwest::Client::new();
    // let res = client.post("https://accounts.spotify.com/api/token")
    //     .form(&params)
    //     .send()
    //     .await.unwrap();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &("http://".to_string() + origin + &"/authorizesuccess".to_string())),
        /*("client_id", &env::var("SPOTIFY_CLIENT_ID").unwrap()),
        ("client_secret", &env::var("SPOTIFY_CLIENT_SECRET").unwrap())*/];
    let auth_string = "Basic ".to_string() + &BASE64_STANDARD.encode(env::var("SPOTIFY_CLIENT_ID").unwrap() + &":".to_string() + &env::var("SPOTIFY_CLIENT_SECRET").unwrap());
    let client = reqwest::Client::new();
    let res = client
        .post("https://accounts.spotify.com/api/token")
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("Authorization", auth_string)
        .form(&params)
        .send().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    println!("{}",v);
    let token = v["access_token"].to_string().replace("\"", "");
    let token_type = v["token_type"].to_string().replace("\"", "");
    let expires_timestamp = chrono::Utc::now() + Duration::seconds(v["expires_in"].as_i64().unwrap());
    let refresh_token = v["refresh_token"].to_string().replace("\"", "");
    println!("Received refresh_token: {}", &refresh_token);
    crate::modules::database::oauth_info::set_token_info(&uuid, &token, &token_type, &expires_timestamp, &refresh_token);
    v["access_token"].to_string()
}

async fn test(ConnectInfo(addr): ConnectInfo<SocketAddr>, request: Request) -> &'static str {
    println!("Received request to /test");
    println!("{}", addr);
    println!("{:?}", request);
    "test"
}

#[axum::debug_handler]
#[allow(unused_must_use)]
async fn testscrape() -> impl axum::response::IntoResponse {
    println!("Received request to /testscrape");
    crate::modules::scraper::do_task_without_time_check().await;
    "response"
}

async fn testapi() -> impl axum::response::IntoResponse {
    println!("Received request to /testapi");
    let auth_string = "Bearer ".to_string() + &"BQDhh-eXILrxli0iMaPyI-FIhGbQjBEw3eRfv7HkUjuDj4cZP7XJqLvW9RWDmIh5gojEMaV2VYtc91pyMY9ko7llU2XnaDf-n9cOLk0nN4j1PZwxpuB2n4i9JsM1kv4JL_9IphEpBZcZllQ5HJgur2W8R4T7WunqicEkJtgEzumhzqRyJwS6KjIn".to_string();
    let client = Client::new();
    let res: String = client
        .get("https://api.spotify.com/v1/me")
        .header("Authorization", auth_string)
        .send().await.unwrap().text().await.unwrap();
    println!("{}", res);
    "response"
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
    //Check if username exists already (Error)
    if crate::modules::database::profile_info::if_username_exists(&username.to_string()) {
        let string = "{\"status\":\"usernameexists\"}";
        let json_value: Value = serde_json::from_str(string).unwrap();
        return Json(json_value);
    }
    //
    let hashed_password = payload.get("hashed_password").unwrap().as_str().unwrap();
    let salt = payload.get("salt").unwrap().as_str().unwrap();
    println!("{}\n{}\n{}", username, hashed_password, salt);
    let uuid = Uuid::new_v4().to_string();
    crate::modules::database::profile_info::set_account_info(&uuid, username, hashed_password, salt).unwrap();
    println!("Set account info");
    //
    let token = crate::modules::encryption::logintoken::request_generate_token_for_uuid(&uuid);
    let string = format!(r#"{{
        "status": "accountcreated",
        "token": "{}"
    }}"#, &token);
    let json_value: Value = serde_json::from_str(&string).unwrap();
    return Json(json_value);
}

async fn login(jar: CookieJar) -> impl axum::response::IntoResponse {
    println!("Received request to /login");
    if jar.get("token").is_some() {
        return axum::response::Response::builder()
            .status(StatusCode::FOUND) // 302 Found
            .header("Location", "/dashboard")  // Redirect to the root path
            .body(body::Body::empty())
            .unwrap();
    }
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
    // println!("{:?}", profile);
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
        let profile = profile.unwrap();
        if profile.hashed_password.eq(&hashed_password) {
            // println!("Passwords match!");
            //Invalidate nonce
            crate::modules::encryption::loginnonce::remove_nonce(nonce);
            //Register token
            let token = crate::modules::encryption::logintoken::request_generate_token_for_uuid(&profile.uuid);
            let string = format!(r#"{{
                "status": "correctpassword",
                "token": "{}"
            }}"#, &token);
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

async fn logout(jar: CookieJar) -> impl axum::response::IntoResponse {
    println!("Received request to /logout");
    if jar.get("token").is_none() {
        return axum::response::Response::builder()
            .status(StatusCode::FOUND) // 302 Found
            .header("Location", "/")  // Redirect to the root path
            .body(body::Body::empty())
            .unwrap();
    }
    let path = Path::new("assets/logout.html");
    // Read the file asynchronously
    let mut file = File::open(path).await.unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.unwrap();
    axum::response::Response::builder()
        .header("Content-Type", "text/html")
        .body(body::Body::from(contents))
        .unwrap()
}

pub fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // Begin nonce cleanup task
            tokio::spawn(crate::modules::encryption::loginnonce::cleanup_nonces());
            tokio::spawn(crate::modules::database::logintoken_info::cleanup_tokens());

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
                .route("/logout", get(logout))
                .route("/test", get(test))
                .route("/testscrape", get(testscrape))
                .route("/testapi", get(testapi));

            let listener = tokio::net::TcpListener::bind("0.0.0.0:35565").await.unwrap();
            //Swapped for alternative below because we need client IP
            axum::serve(listener, app).await.unwrap();
            // axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
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