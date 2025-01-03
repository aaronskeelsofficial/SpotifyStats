use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use chrono::Duration;

#[get("/")]
async fn index() -> impl Responder {
    "Hello, World!"
}

#[get("/authorize")]
async fn authorize() -> impl Responder {
    println!("Received request to /authorize");
    let base_url = "https://accounts.spotify.com/authorize".to_string();
    let client_id = "?client_id=260c8b1e828041f8a6120f9eea11c15c".to_string();
    let response_type = "&response_type=code".to_string();
    let redirect_uri = "&redirect_uri=http://206.13.112.71:35565/authorizesuccess".to_string();
    let scope = "&scope=user-read-recently-played".to_string();
    let full_url = base_url + &client_id + &response_type + &redirect_uri + &scope;
    println!("Redirection to Spotify");
    HttpResponse::Found()
        .append_header(("Location", full_url))
        .finish()
}

#[derive(serde::Deserialize)]
struct AuthorizeSuccessQuery {
    code: String,
}
#[get("/authorizesuccess")]
async fn authorizesuccess(req: HttpRequest, lsq: web::Query<AuthorizeSuccessQuery>) -> impl Responder {
    println!("Received request to /authorizeuccess");
    let code = &lsq.0.code;
    let ip = &req.peer_addr().unwrap().to_string();
    println!("Setting access code");
    crate::modules::database::oath_info::set_access_code(&ip, &code).unwrap();
    println!("Trading code for token");
    let _token = trade_code_for_token(&req, &ip, &code).await;
    println!("Received code and token");
    HttpResponse::Found()
        .append_header(("Location", "/dashboard"))
        .finish()
}
async fn trade_code_for_token(req: &HttpRequest, ip: &String, code: &String) -> String {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &("http://".to_string() + &req.connection_info().host().to_string() + &"/authorizesuccess".to_string())),
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

#[get("/test")]
async fn test(req: HttpRequest) -> impl Responder {
    println!("Received request to /test");
    println!("{}", req.method().to_string());
    println!("--");
    println!("{}", req.path().to_string());
    println!("--");
    println!("{},{},{}", req.connection_info().realip_remote_addr().unwrap().to_string(), req.peer_addr().unwrap().to_string(), req.connection_info().host().to_string());
    println!("--");
    println!("{}", &("http://".to_string() + &req.connection_info().host().to_string() + &"/loginsuccess".to_string()));
    // for (key,value) in req.headers().iter() {
    //     println!("{}:{}", key.to_string(), value.to_str().unwrap());
    // }
    "test"
}

#[get("/signup")]
async fn signup() -> impl Responder {
    println!("Received request to /signup");
    let html_content = std::fs::read_to_string("assets/signup.html").unwrap();
    HttpResponse::Ok()
        .content_type("text/html")
        .body(html_content)
}

#[derive(serde::Deserialize)]
struct SignupSubmitQuery {
    username: String,
    hashed_password: String,
    salt: String,
}
#[post("/signupsubmit")]
async fn signupsubmit(ssq: web::Json<SignupSubmitQuery>) -> impl Responder {
    println!("Received request to /signupsubmit");
    let username = &ssq.0.username;
    let hashed_password = &ssq.0.hashed_password;
    let salt = &ssq.0.salt;
    println!("{}\n{}\n{}", username, hashed_password, salt);
    "Hello"
}

// #[get("/{name}")]
// async fn hello(name: web::Path<String>) -> impl Responder {
//     format!("Hello {}!", &name)
// }

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    println!("Attempting to run Web Server on port 35565");
    let server = HttpServer::new(
        || App::new()
        .service(index)
        .service(authorize)
        .service(authorizesuccess)
        .service(signup)
        .service(signupsubmit)
        .service(test))
        .bind(("0.0.0.0", 35565))?
        .run()
        .await;
    return server;
}

// look into account handling
//     1 account can have multiple profiles
// look into setting cookie to store token
//     if they have token stored and not expired, dont get it again
// look into persistent authorization to do automatic backups every night

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
