use std::sync::Mutex;
use crate::modules::scraper::PlayHistoryObject;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, Result};
use serde::Serialize;

lazy_static! {
    static ref LISTENHISTORYINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/listen_history_info.db").unwrap());
}

pub fn first_init_if_necessary() {
    let conn_guard = LISTENHISTORYINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS listen_history_info
        (
            spotifyid TEXT,
            trackhashid TEXT,
            artists TEXT,
            albumspotifyid TEXT,
            timestamp TEXT,
            UNIQUE (spotifyid,trackhashid,artists,albumspotifyid,timestamp)
        )",
        [],
    ).unwrap();
}

pub fn register_listen(spotifyid: &String, pho: &PlayHistoryObject) -> Result<()> {
    let conn_guard = LISTENHISTORYINFO_CONN.lock().unwrap();
    // Insert some data into the table
    let trackhashid = &pho.track.get_hashid();
    let artists = crate::modules::database::artist_info::artist_vec_to_json(&pho.track.artists);
    let albumspotifyid = &pho.track.album.id;
    let timestamp = &pho.played_at;
    conn_guard.execute(
        "INSERT OR IGNORE INTO listen_history_info (spotifyid,trackhashid,artists,albumspotifyid,timestamp)
        VALUES (?1,?2,?3,?4,?5)",
        params![spotifyid,trackhashid,&artists,albumspotifyid,timestamp],
    )?;

    Ok(())
}

#[derive(Serialize)]
struct ListenHistoryJsonObject {
    spotifyid: String,
    trackhashid: String,
    artists: String,
    albumspotifyid: String,
    timestamp: String,
}
pub fn get_info_as_json(spotifyids: Vec<String>) -> String {
    let conn_guard = LISTENHISTORYINFO_CONN.lock().unwrap();
    let mut stmt = conn_guard.prepare(&format!(
        "SELECT spotifyid,trackhashid,artists,albumspotifyid,timestamp
        FROM listen_history_info
        WHERE spotifyid IN ({})",
        spotifyids.iter().map(|_| "?".to_string()).collect::<Vec<String>>().join(",")))
        .unwrap();
    let info_iter = stmt.query_map(rusqlite::params_from_iter(spotifyids.iter()), |row| {
        Ok(ListenHistoryJsonObject {
            spotifyid: row.get(0)?,
            trackhashid: row.get(1)?,
            artists: row.get(2)?,
            albumspotifyid: row.get(3)?,
            timestamp: row.get(4)?,
        })
    }).unwrap();
    let mut info_list: Vec<ListenHistoryJsonObject> = Vec::new();
    for info in info_iter {
        info_list.push(info.unwrap());
    }
    let json_result = serde_json::to_string(&info_list).unwrap();
    return json_result;
}

// test that this function works and hook it up to webserver