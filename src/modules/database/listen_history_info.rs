use std::sync::{Mutex, MutexGuard};
use crate::modules::scraper::PlayHistoryObject;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, OptionalExtension, Result};
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
    ////////////////
    let albumspotifyid: String;
        //  Case 1. If the album is a single (not actually an album)
    if pho.track.album.album_type.eq("single") {
        //Check if album already exists and use that or use "" to signify no album (we will replace this later if an album comes along)
        let tempval = get_album_if_exists(trackhashid, &conn_guard);
        match tempval {
            Some(albumspotifyid_inner) => {
                albumspotifyid = albumspotifyid_inner;
            },
            None => {
                albumspotifyid = "".to_string();
            },
        };
    }
        //  Case 2. If the album is truly an album
    else {
        albumspotifyid = pho.track.album.id.clone();
        //Update all pre-existing listen_history entries with same trackhashid and album "" placeholder;
        conn_guard.execute(
            "UPDATE listen_history_info
            SET albumspotifyid = ?1
            WHERE trackhashid = ?2
                AND albumspotifyid = ''",
            params![&albumspotifyid, trackhashid])
        .unwrap();
    }
    ////////////////
    let timestamp = &pho.played_at;
    conn_guard.execute(
        "INSERT OR IGNORE INTO listen_history_info (spotifyid,trackhashid,artists,albumspotifyid,timestamp)
        VALUES (?1,?2,?3,?4,?5)",
        params![spotifyid,trackhashid,&artists,&albumspotifyid,timestamp],
    )?;

    Ok(())
}

fn get_album_if_exists(trackhashid: &String, conn_guard: &MutexGuard<Connection>) -> Option<String> {
    // let conn_guard: MutexGuard<'_, Connection> = LISTENHISTORYINFO_CONN.lock().unwrap();
    let mut stmt = conn_guard.prepare(
        "SELECT albumspotifyid
        FROM listen_history_info
        WHERE trackhashid = ?1").unwrap();
        let result: Result<Option<String>, rusqlite::Error> = stmt.query_row(params![trackhashid], |row| {
            row.get(0).optional()
        });
        match result {
            Ok(Some(albumspotifyid)) => Some(albumspotifyid),  // If the album exists, return it.
            Ok(None) => None,                // If the album does not exist, return None.
            Err(_) => None,                  // Handle any errors gracefully and return None.
        }
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