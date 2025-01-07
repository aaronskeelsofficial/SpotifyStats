use std::sync::Mutex;

use rusqlite::{params, Connection, Result};
use lazy_static::lazy_static;

lazy_static! {
    static ref PROFILEINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/profile_info.db").unwrap());
}

pub fn first_init_if_necessary() {
    let conn_guard = PROFILEINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS profile_info
        (
            uuid TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        )",
        [],
    ).unwrap();
}

pub fn set_account_info(uuid: &String, username: &str, hashed_password: &str, salt: &str) -> Result<()> {
    let conn_guard = PROFILEINFO_CONN.lock().unwrap();
    // Insert some data into the table
    conn_guard.execute(
        "INSERT INTO profile_info (uuid,username,hashed_password,salt)
        VALUES (?1,?2,?3,?4)
        ON CONFLICT (uuid)
        DO UPDATE SET
            username = EXCLUDED.username,
            hashed_password = EXCLUDED.hashed_password,
            salt = EXCLUDED.salt",
        params![uuid, username, hashed_password, salt],
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub uuid: String,
    pub username: String,
    pub hashed_password: String,
    pub salt: String,
}
pub fn get_account_info(username: &str) -> Result<ProfileInfo> {
    let conn_guard = PROFILEINFO_CONN.lock().unwrap();
    let query = conn_guard.query_row(
        "SELECT uuid,username,hashed_password,salt
        FROM profile_info
        WHERE username = ?1",
        [username],
        |row| {
            Ok(ProfileInfo {
                uuid: row.get(0)?,
                username: row.get(1)?,
                hashed_password: row.get(2)?,
                salt: row.get(3)?,
            })
        },
    );
    return query;
}

pub fn if_username_exists(username: &String) -> bool {
    let conn_guard = PROFILEINFO_CONN.lock().unwrap();
    let mut stmt = conn_guard.prepare("SELECT 1 FROM profile_info WHERE username = ? LIMIT 1").unwrap();
    let mut rows = stmt.query(params![username]).unwrap();
    rows.next().unwrap().is_some()
}