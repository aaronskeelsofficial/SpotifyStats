use std::sync::Mutex;
use crate::modules::scraper::PlayHistoryObject;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, Result};

lazy_static! {
    static ref LISTENHISTORYINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/listen_history_info.db").unwrap());
}

pub fn register_listen(uuid: &String, pho: &PlayHistoryObject) -> Result<()> {
    let conn_guard = LISTENHISTORYINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS listen_history_info
        (
            uuid TEXT,
            trackhashid TEXT,
            artists TEXT,
            albumspotifyid TEXT,
            timestamp TEXT,
            UNIQUE (uuid, trackhashid, artists, albumspotifyid, timestamp)
        )",
        [],
    )?;
    // Insert some data into the table
    let trackhashid = &pho.track.get_hashid();
    let artists = crate::modules::database::artist_info::artist_vec_to_json(&pho.track.artists);
    let albumspotifyid = &pho.track.album.id;
    let timestamp = &pho.played_at;
    conn_guard.execute(
        "INSERT OR IGNORE INTO listen_history_info (uuid,trackhashid,artists,albumspotifyid,timestamp)
        VALUES (?1,?2,?3,?4,?5)",
        params![uuid,trackhashid,&artists,albumspotifyid,timestamp],
    )?;

    Ok(())
}