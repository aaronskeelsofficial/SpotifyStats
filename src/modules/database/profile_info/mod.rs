use rusqlite::{params, Connection, Result};

pub fn set_account_info(uuid: &String, username: &str, hashed_password: &str, salt: &str) -> Result<()> {
    // Specify the path to the SQLite database file
    let db_path = "assets/profile_info.db";
    // Open the connection to the SQLite database file
    let conn = Connection::open(db_path)?;
    // Create a table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS profile_info
        (
            uuid TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        )",
        [],
    )?;
    // Insert some data into the table
    conn.execute(
        "INSERT INTO profile_info (uuid,username,hashed_password,salt)
        VALUES (?1,?2,?3,?4)
        ON CONFLICT (uuid)
        DO UPDATE SET
            username = EXCLUDED.username,
            hashed_password = EXCLUDED.hashed_password,
            salt = EXCLUDED.salt",
        params![uuid, username, hashed_password, salt],
    )?;
    conn.close().unwrap();
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
    let db_path = "assets/profile_info.db";
    let conn = Connection::open(db_path).unwrap();
    let query = conn.query_row(
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