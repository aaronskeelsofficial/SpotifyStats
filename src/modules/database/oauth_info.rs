use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref OAUTHINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/oauth_info.db").unwrap());
}

pub fn set_access_code(uuid: &String, code: &String) -> Result<()> {
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
    )?;
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
        VALUES (?1,?2,?3,?4,?5,?6)
        ON CONFLICT (uuid)
        DO UPDATE SET
            token = EXCLUDED.token,
            tokentype = EXCLUDED.tokentype,
            expirestimestamp = EXCLUDED.expirestimestamp,
            refreshtoken = EXCLUDED.refreshtoken",
        params![&uuid, &token, &token_type, &expires_timestamp.to_rfc3339().to_string(), refresh_token],
    ).unwrap();
}

pub fn cleanse_invalid_info() {
    let conn_guard = OAUTHINFO_CONN.lock().unwrap();
    let now = Utc::now().to_rfc3339().to_string();
    conn_guard.execute(
        "DELETE FROM oauth_info
        WHERE expirestimestamp < ?1",
        params![&now],
    ).unwrap();
}