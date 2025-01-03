use std::{collections::HashMap, net::SocketAddr, path::Path};
use axum::{body, extract::{ConnectInfo, Query, Request}, http::HeaderMap, routing::{get, post}, Json, Router };
use chrono::Duration;
use serde_json::Value;
use tokio::{fs::File, io::AsyncReadExt};

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
    "Hello"
}

pub fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // build our application with a route
            let app = Router::new()
                .route("/", get(index))
                .route("/authorize", get(authorize))
                .route("/authorizesuccess", get(authorizesuccess))
                .route("/signup", get(signup))
                .route("/signupsubmit", post(signupsubmit))
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