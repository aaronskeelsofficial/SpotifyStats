use std::sync::Mutex;

use crate::modules::scraper::Artist;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, OptionalExtension, Result};
use serde::Serialize;

lazy_static! {
    static ref ARTISTINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/artist_info.db").unwrap());
}

pub fn first_init_if_necessary() {
    let conn_guard = ARTISTINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS artist_info
        (
            spotifyid TEXT PRIMARY KEY,
            name TEXT,
            images TEXT
        )",
        [],
    ).unwrap();
}

pub fn _register_artist(artist: &Artist) -> Result<()> {
    let conn_guard = ARTISTINFO_CONN.lock().unwrap();
    // Insert some data into the table
    conn_guard.execute(
        "INSERT OR IGNORE INTO artist_info (spotifyid,name)
        VALUES (?1,?2)",
        params![artist.id, artist.name],
    )?;

    Ok(())
}

pub fn register_artist_with_image_updates(artist: &Artist) -> Result<()> {
    let conn_guard = ARTISTINFO_CONN.lock().unwrap();
    let images = artist.get_images_json();
    /* This second approach is necessary because allegedly albums update cover art long after release, so we need to account
    * for that
    */
    // First, check if the artist already exists by spotifyid
    let mut stmt = conn_guard.prepare("SELECT images FROM artist_info WHERE spotifyid = ?1")?;
    let existing_images: Option<String> = stmt.query_row(params![&artist.id], |row| row.get(0)).optional()?;
    // If the album exists and the images are different, update the row
    if let Some(existing_images_value) = existing_images {
        if existing_images_value != images {
            // If the images are different, update the row with new values
            let update_query = "
                UPDATE artist_info
                SET name = ?2, images = ?3
                WHERE spotifyid = ?1
            ";
            conn_guard.execute(update_query, params![&artist.id, &artist.name, &images])?;
        }
    } else {
        // If the album doesn't exist, insert the new row
        let insert_query = "
            INSERT INTO artist_info (spotifyid, name, images)
            VALUES (?1, ?2, ?3)
        ";
        conn_guard.execute(insert_query, params![artist.id, artist.name, images])?;
    }

    Ok(())
}

pub fn artist_vec_to_json(artists: &Vec<Artist>) -> String {
    let id_vec: Vec<String> = artists.iter().map(|artist| artist.id.clone()).collect();
    let json_id_array = serde_json::to_string(&id_vec).unwrap();
    return json_id_array;
}

pub fn artist_vec_to_comma_sep_string(artists: &Vec<Artist>) -> String {
    let comma_separated_string: String = artists
        .iter()
        .map(|artist| artist.id.clone())
        .collect::<Vec<String>>()
        .join(",");  // Join by comma
    return comma_separated_string;
}

#[derive(Serialize)]
struct ArtistJsonObject {
    spotifyid: String,
    name: String,
    images: String,
}
pub fn get_info_as_json() -> String {
    let conn_guard = ARTISTINFO_CONN.lock().unwrap();
    let mut stmt = conn_guard.prepare("SELECT spotifyid,name,images FROM artist_info").unwrap();
    let info_iter = stmt.query_map(params![], |row| {
        Ok(ArtistJsonObject {
            spotifyid: row.get(0)?,
            name: row.get(1)?,
            images: row.get(2)?,
        })
    }).unwrap();
    let mut info_list: Vec<ArtistJsonObject> = Vec::new();
    for info in info_iter {
        info_list.push(info.unwrap());
    }
    let json_result = serde_json::to_string(&info_list).unwrap();
    return json_result;
}