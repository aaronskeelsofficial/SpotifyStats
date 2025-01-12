use std::{collections::HashMap, env, sync::Mutex};
use base64::prelude::*;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use rusqlite::{params, Connection};
use lazy_static::lazy_static;
use serde_json::json;

lazy_static! {
    pub static ref OAUTHINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/oauth_info.db").unwrap());
    // pub static ref TEMP_ACCESS_CODE: Mutex<HashMap<String,String>> = Mutex::new(HashMap::new());
}

pub fn first_init_if_necessary() {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS oauth_info
        (
            uuid TEXT,
            spotifyid TEXT,
            displayname TEXT,
            token TEXT,
            tokentype TEXT,
            expirestimestamp TEXT,
            refreshtoken TEXT,
            UNIQUE (uuid,spotifyid)
        )",
        [],
    ).unwrap();
}

// pub fn set_access_code(uuid: &String, code: &String) -> Result<()> {
//     let mut map_guard = TEMP_ACCESS_CODE.lock().unwrap();
//     map_guard.insert(uuid.clone(), code.clone());

//     Ok(())
// }

pub fn set_token_info(uuid: &String, spotifyid: &String, displayname: &String, token: &String, token_type: &String, expires_timestamp: &DateTime<Utc>, refresh_token: &String) {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    conn_guard.execute(
        "INSERT OR REPLACE INTO oauth_info (uuid,spotifyid,displayname,token,tokentype,expirestimestamp,refreshtoken)
        VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![&uuid, spotifyid, displayname, &token, &token_type, &expires_timestamp.to_rfc3339().to_string(), refresh_token],
    ).unwrap();
}

pub fn revalidate_token(uuid: &String, spotifyid: &String, displayname: &String, refreshtoken: &String) {
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
    crate::modules::database::oauth_info::set_token_info(&uuid, spotifyid, displayname, &token, &token_type, &expires_timestamp, &refresh_token);
}

pub fn revalidate_invalid_info() {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    let token_iter: Vec<(String, String, String, String)> = {
        let now = Utc::now().to_rfc3339().to_string();
        let query = "
            SELECT uuid,spotifyid,displayname,refreshtoken
            FROM oauth_info
            WHERE expirestimestamp < ?1
        ";
        // Prepare the statement
        let stmt = &mut conn_guard.prepare(query).unwrap();
        // Execute the query and loop through the results
        stmt.query_map(params![now], |row| {
            Ok((
                row.get::<_, String>(0)?, // uuid
                row.get::<_, String>(1)?, // spotifyid
                row.get::<_, String>(2)?, // displayname
                row.get::<_, String>(3)?, // refreshtoken
            ))
        })
        .unwrap()
        .filter_map(|result| result.ok())
        .map(|(uuid, spotifyid, displayname, refreshtoken)| {
            (uuid.clone(), spotifyid.clone(), displayname.clone(), refreshtoken.clone())
        })
        .collect()
    };
    drop(conn_guard);

    // Iterate over the expired tokens
    for token in token_iter {
        match token {
            (uuid, spotifyid, displayname, refreshtoken) => {
                revalidate_token(&uuid, &spotifyid, &displayname, &refreshtoken);
                println!("Revalidating expired token...");
            }
        }
    }
}

pub fn get_spotifyids_from_uuid(uuid: &String) -> Vec<String> {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    let spotifyids: Vec<String> = {
        let query = "
            SELECT spotifyid
            FROM oauth_info
            WHERE uuid = ?1
        ";
        // Prepare the statement
        let stmt = &mut conn_guard.prepare(query).unwrap();
        // Execute the query and loop through the results
        stmt.query_map(params![uuid], |row| {
            Ok(row.get::<_, String>(0)?)
        })
        .unwrap()
        .filter_map(|result| result.ok())
        .map(|spotifyid| {
            spotifyid.clone()
        })
        .collect()
    };
    return spotifyids;
}

pub fn get_spotifyid_to_displayname_map_json_string(uuid: &String) -> String {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    let mut result_map: HashMap<String, String> = HashMap::new();
    let query = "
        SELECT spotifyid, displayname
        FROM oauth_info
        WHERE uuid = ?1
    ";
    // Prepare the statement
    let stmt = &mut conn_guard.prepare(query).unwrap();
    // Execute the query and populate the HashMap
    stmt.query_map(params![uuid], |row| {
        let spotifyid: String = row.get(0)?;
        let displayname: String = row.get(1)?;
        Ok((spotifyid, displayname))
    })
    .unwrap()
    .for_each(|result| {
        if let Ok((spotifyid, displayname)) = result {
            result_map.insert(spotifyid, displayname);
        }
    });
    // Serialize the HashMap to JSON string
    let json_data = json!(result_map);

    // Return the JSON string
    json_data.to_string()
}