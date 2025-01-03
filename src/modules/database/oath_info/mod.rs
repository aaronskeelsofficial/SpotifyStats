use chrono::{DateTime, Timelike, Utc};
use rusqlite::{params, Connection, Result};

pub fn set_access_code(ip: &String, code: &String) -> Result<()> {
    // Specify the path to the SQLite database file
    let db_path = "assets/oauth.db";

    // Open the connection to the SQLite database file
    let conn = Connection::open(db_path)?;

    // Create a table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS oauth_info
        (
            ip TEXT PRIMARY KEY,
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
    conn.execute(
        "INSERT INTO oauth_info (ip,code)
        VALUES (?1,?2)
        ON CONFLICT (ip)
        DO UPDATE SET code = EXCLUDED.code",
        params![&ip, &code],
    )?;

    conn.close().unwrap();

    Ok(())
}

pub fn set_token_info(ip: &String, token: &String, token_type: &String, expires_timestamp: &DateTime<Utc>, refresh_token: &String) {
    let db_path = "assets/oauth.db";
    let conn = Connection::open(db_path).unwrap();
    conn.execute(
        "INSERT INTO oauth_info (ip,token,tokentype,expiresseconds,expiresnanoseconds,refreshtoken)
        VALUES (?1,?2,?3,?4,?5,?6)
        ON CONFLICT (ip)
        DO UPDATE SET
            token = EXCLUDED.token,
            tokentype = EXCLUDED.tokentype,
            expiresseconds = EXCLUDED.expiresseconds,
            expiresnanoseconds = EXCLUDED.expiresnanoseconds,
            refreshtoken = EXCLUDED.refreshtoken",
        params![&ip, &token, &token_type, &expires_timestamp.timestamp(), &expires_timestamp.nanosecond(), refresh_token],
    ).unwrap();
    conn.close().unwrap();
}