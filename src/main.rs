use rusqlite::{params, Connection, Result};

fn main() -> Result<()> {
    // Specify the path to the SQLite database file
    let db_path = "database.db"; // This will create or open a file called "database.db"

    // Open the connection to the SQLite database file
    let conn = Connection::open(db_path)?;

    // Create a table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS spotify_api_info (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )",
        [],
    )?;

    // Insert some data into the table
    conn.execute(
        "INSERT INTO spotify_api_info (name) VALUES (?1)",
        params!["Alice"],
    )?;
    conn.execute(
        "INSERT INTO spotify_api_info (name) VALUES (?1)",
        params!["Bob"],
    )?;

    // Query the database
    let mut stmt = conn.prepare("SELECT id, name FROM spotify_api_info")?;
    let person_iter = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;

    // Print the results
    for person in person_iter.into_iter() {
        let (id, name): (i64, String) = person?;
        println!("Person: {} - {}", id, name);
    }

    Ok(())
}