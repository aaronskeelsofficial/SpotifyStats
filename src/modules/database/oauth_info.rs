use std::{env, sync::Mutex};
use base64::prelude::*;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use rusqlite::{params, Connection, Result};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref OAUTHINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/oauth_info.db").unwrap());
}

pub fn first_init_if_necessary() {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS oauth_info
        (
            uuid TEXT PRIMARY KEY,
            code TEXT,
            token TEXT,
            tokentype TEXT,
            expirestimestamp TEXT,
            refreshtoken TEXT
        )",
        [],
    ).unwrap();
}

pub fn set_access_code(uuid: &String, code: &String) -> Result<()> {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    // Insert some data into the table
    conn_guard.execute(
        "INSERT INTO oauth_info (uuid,code)
        VALUES (?1,?2)
        ON CONFLICT (uuid)
        DO UPDATE SET
            code = EXCLUDED.code",
        params![&uuid, &code],
    )?;

    Ok(())
}

pub fn set_token_info(uuid: &String, token: &String, token_type: &String, expires_timestamp: &DateTime<Utc>, refresh_token: &String) {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    conn_guard.execute(
        "INSERT INTO oauth_info (uuid,token,tokentype,expirestimestamp,refreshtoken)
        VALUES (?1,?2,?3,?4,?5)
        ON CONFLICT (uuid)
        DO UPDATE SET
            token = EXCLUDED.token,
            tokentype = EXCLUDED.tokentype,
            expirestimestamp = EXCLUDED.expirestimestamp,
            refreshtoken = EXCLUDED.refreshtoken",
        params![&uuid, &token, &token_type, &expires_timestamp.to_rfc3339().to_string(), refresh_token],
    ).unwrap();
}

pub fn revalidate_token(uuid: &String, refreshtoken: &String) {
    //  Use refresh token to get new authentication token
    println!("Using refresh token to get new authentication token");
    let form_data = [
        ("grant_type", "refresh_token"),
        ("refresh_token", &refreshtoken),
    ];
    let auth_string = "Basic ".to_string() + &BASE64_STANDARD.encode(env::var("SPOTIFY_CLIENT_ID").unwrap() + &":".to_string() + &env::var("SPOTIFY_CLIENT_SECRET").unwrap());
    let client = Client::new();
    let res: String = tokio::runtime::Runtime::new().unwrap().block_on(async {
        client
            .post("https://accounts.spotify.com/api/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("Authorization", auth_string)
            .form(&form_data)
            .send().await.unwrap().text().await.unwrap()
    });
    println!("{}", res);
    let v: serde_json::Value = serde_json::from_str(&res).unwrap();
    //  Update database with new authentication token
    println!("Updating database with new auth token");
    let token = v["access_token"].to_string().replace("\"", "");
    let token_type = v["token_type"].to_string().replace("\"", "");
    let expires_timestamp = chrono::Utc::now() + Duration::seconds(v["expires_in"].as_i64().unwrap());
    let mut refresh_token = refreshtoken.clone();
    if v.get("refresh_token").is_some() {
        refresh_token = v.get("refresh_token").unwrap().to_string();
    }
    crate::modules::database::oauth_info::set_token_info(&uuid, &token, &token_type, &expires_timestamp, &refresh_token);
}

pub fn revalidate_invalid_info() {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    let token_iter: Vec<(String, String)> = {
        let now = Utc::now().to_rfc3339().to_string();
        let query = "
            SELECT uuid, refreshtoken
            FROM oauth_info
            WHERE expirestimestamp < ?1
        ";
        // Prepare the statement
        let stmt = &mut conn_guard.prepare(query).unwrap();
        // Execute the query and loop through the results
        stmt.query_map(params![now], |row| {
            Ok((
                row.get::<_, String>(0)?, // uuid
                row.get::<_, String>(1)?, // refreshtoken
            ))
        })
        .unwrap()
        .filter_map(|result| result.ok())
        .map(|(uuid, refreshtoken)| {
            (uuid.clone(), refreshtoken.clone())
        })
        .collect()
    };
    drop(conn_guard);

    // Iterate over the expired tokens
    for token in token_iter {
        match token {
            (uuid, refreshtoken) => {
                revalidate_token(&uuid, &refreshtoken);
                println!("Revalidating expired token...");
            }
        }
    }
}