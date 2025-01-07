use std::sync::Mutex;

use chrono::Utc;
use rusqlite::{params, Connection, Result};
use lazy_static::lazy_static;
use tokio::time::sleep;

lazy_static! {
    static ref LOGININFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/logintoken_info.db").unwrap());
}

pub fn first_init_if_necessary() {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS logintoken_info
        (
            token TEXT PRIMARY KEY,
            uuid TEXT NOT NULL,
            lastusedtimestamp TEXT NOT NULL
        )",
        [],
    ).unwrap();
}

#[derive(Debug)]
pub struct LoginTokenInfo {
    pub token: Option<String>,
    pub uuid: Option<String>,
    pub last_used_timestamp: Option<String>,
}

pub const TOKEN_TOKIO_CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(60*20);
pub const TOKEN_CHRONOLIFETIME: chrono::Duration = chrono::Duration::seconds(60*20);
// pub const TOKEN_TOKIOLIFETIME: tokio::time::Duration = tokio::time::Duration::from_secs(5);
// pub const TOKEN_CHRONOLIFETIME: chrono::Duration = chrono::Duration::seconds(30);
pub async fn cleanup_tokens() {
    loop {
        sleep(TOKEN_TOKIO_CLEANUP_INTERVAL).await;
        let now = Utc::now();
        let death_point = now - TOKEN_CHRONOLIFETIME;
        let conn_guard = LOGININFO_CONN.lock().unwrap();
        conn_guard.execute(
            "DELETE FROM logintoken_info
            WHERE lastusedtimestamp <= ?1",
            params![death_point.to_rfc3339().to_string()]
        ).unwrap();
        println!("LoginToken cleanup complete");
    }
}

pub fn set_token_info(token: &String, uuid: &String, last_used_timestamp: &String) -> Result<()> {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    // Insert some data into the table
    conn_guard.execute(
        "INSERT INTO logintoken_info (token,uuid,lastusedtimestamp)
        VALUES (?1,?2,?3)
        ON CONFLICT (token)
        DO UPDATE SET
            uuid = EXCLUDED.uuid,
            lastusedtimestamp = EXCLUDED.lastusedtimestamp",
        params![token, uuid, last_used_timestamp],
    )?;
    Ok(())
}

pub fn get_uuid_from_token(token: &String) -> Result<String> {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    let query = conn_guard.query_row(
        "SELECT uuid
        FROM logintoken_info
        WHERE token = ?1",
        [token],
        |row| {
            let uuid = row.get(0)?;
            Ok(uuid)
        },
    );
    return query;
}

pub fn get_lastusedtimestamp_from_token(token: &String) -> Result<String> {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    let query = conn_guard.query_row(
        "SELECT lastusedtimestamp
        FROM logintoken_info
        WHERE token = ?1",
        [token],
        |row| {
            let lastusedtimestamp = row.get(0)?;
            Ok(lastusedtimestamp)
        },
    );
    return query;
}

pub fn get_logintokeninfo_from_uuid(uuid: &String) -> Result<LoginTokenInfo> {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    let query = conn_guard.query_row(
        "SELECT token,lastusedtimestamp
        FROM logintoken_info
        WHERE uuid = ?1",
        [uuid],
        |row| {
            let token = row.get(0)?;
            let last_used_timestamp = row.get(1)?;
            Ok(LoginTokenInfo {
                token: Some(token),
                uuid: Some(uuid.clone()),
                last_used_timestamp: Some(last_used_timestamp),
            })
        },
    );
    return query;
}

pub fn get_logintokeninfo_from_token(token: &String) -> Result<LoginTokenInfo> {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    let query = conn_guard.query_row(
        "SELECT uuid,lastusedtimestamp
        FROM logintoken_info
        WHERE token = ?1",
        [token],
        |row| {
            let uuid = row.get(0)?;
            let last_used_timestamp = row.get(1)?;
            Ok(LoginTokenInfo {
                token: Some(token.clone()),
                uuid: Some(uuid),
                last_used_timestamp: Some(last_used_timestamp),
            })
        },
    );
    return query;
}

pub fn remove_token(token: &String) {
    let conn_guard = LOGININFO_CONN.lock().unwrap();
    conn_guard.execute(
        "DELETE FROM logintoken_info
        WHERE token = ?1",
        params![token]
    ).unwrap();
}