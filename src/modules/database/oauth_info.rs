use chrono::{DateTime, Timelike, Utc};
use rusqlite::{params, Connection, Result};
use lazy_static::lazy_static;
use tokio::sync::Mutex;

lazy_static! {
    pub static ref OAUTHINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/oauth_info.db").unwrap());
}

pub async fn set_access_code(uuid: &String, code: &String) -> Result<()> {
    let conn_guard = OAUTHINFO_CONN.lock().await;
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS oauth_info
        (
            uuid TEXT PRIMARY KEY,
            code TEXT,
            token TEXT,
            tokentype TEXT,
            expiresseconds BIGINT,
            expiresnanoseconds INT UNSIGNED,
            refreshtoken TEXT
        )",
        [],
    )?;
    // Insert some data into the table
    conn_guard.execute(
        "INSERT INTO oauth_info (uuid,code)
        VALUES (?1,?2)
        ON CONFLICT (uuid)
        DO UPDATE SET code = EXCLUDED.code",
        params![&uuid, &code],
    )?;

    Ok(())
}

pub async fn set_token_info(uuid: &String, token: &String, token_type: &String, expires_timestamp: &DateTime<Utc>, refresh_token: &String) {
    let conn_guard = OAUTHINFO_CONN.lock().await;
    conn_guard.execute(
        "INSERT INTO oauth_info (uuid,token,tokentype,expiresseconds,expiresnanoseconds,refreshtoken)
        VALUES (?1,?2,?3,?4,?5,?6)
        ON CONFLICT (uuid)
        DO UPDATE SET
            token = EXCLUDED.token,
            tokentype = EXCLUDED.tokentype,
            expiresseconds = EXCLUDED.expiresseconds,
            expiresnanoseconds = EXCLUDED.expiresnanoseconds,
            refreshtoken = EXCLUDED.refreshtoken",
        params![&uuid, &token, &token_type, &expires_timestamp.timestamp(), &expires_timestamp.nanosecond(), refresh_token],
    ).unwrap();
}