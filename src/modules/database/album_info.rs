use std::sync::Mutex;
use crate::modules::scraper::Album;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, OptionalExtension, Result};

lazy_static! {
    static ref ALBUMINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/album_info.db").unwrap());
}

pub fn register_album(album: &Album) -> Result<()> {
    let conn_guard = ALBUMINFO_CONN.lock().unwrap();

    // // Create a table if it doesn't exist
    // conn_guard.execute(
    //     "CREATE TABLE IF NOT EXISTS album_info
    //     (
    //         spotifyid TEXT PRIMARY KEY,
    //         name TEXT,
    //         artists TEXT,
    //         images TEXT,
    //         releasedate TEXT,
    //         releasedateprecision TEXT,
    //         totaltracks INT UNSIGNED
    //     )",
    //     [],
    // )?;
    // // Insert some data into the table
    let artists = crate::modules::database::artist_info::artist_vec_to_json(&album.artists);
    let images = album.get_images_json();
    // conn_guard.execute(
    //     "INSERT OR IGNORE INTO album_info (spotifyid,name,artists,images,releasedate,releasedateprecision,totaltracks)
    //     VALUES (?1,?2,?3,?4,?5,?6,?7)",
    //     params![album.id, album.name, artists, images, album.release_date,album.release_date_precision,album.total_tracks],
    // )?;

    /* This second approach is necessary because allegedly albums update cover art long after release, so we need to account
    * for that
    */
    // First, check if the album already exists by spotifyid
    let mut stmt = conn_guard.prepare("SELECT images FROM album_info WHERE spotifyid = ?1")?;
    let existing_images: Option<String> = stmt.query_row(params![&album.id], |row| row.get(0)).optional()?;
    // If the album exists and the images are different, update the row
    if let Some(existing_images_value) = existing_images {
        if existing_images_value != images {
            // If the images are different, update the row with new values
            let update_query = "
                UPDATE album_info
                SET name = ?2, artists = ?3, images = ?4, releasedate = ?5, releasedateprecision = ?6, totaltracks = ?7
                WHERE spotifyid = ?1
            ";
            conn_guard.execute(update_query, params![album.id, album.name, artists, images, album.release_date,album.release_date_precision,album.total_tracks])?;
        }
    } else {
        // If the album doesn't exist, insert the new row
        let insert_query = "
            INSERT INTO album_info (spotifyid, name, artists, images, releasedate, releasedateprecision, totaltracks)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ";
        conn_guard.execute(insert_query, params![album.id, album.name, artists, images, album.release_date,album.release_date_precision,album.total_tracks])?;
    }

    Ok(())
}