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