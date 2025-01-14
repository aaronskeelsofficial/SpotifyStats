use std::sync::Mutex;
use crate::modules::scraper::Track;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, Result};
use serde::Serialize;

lazy_static! {
    static ref TRACKINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/db/track_info.db").unwrap());
}

pub fn first_init_if_necessary() {
    let conn_guard = TRACKINFO_CONN.lock().unwrap();
    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS track_info
        (
            hashid TEXT PRIMARY KEY,
            spotifyid TEXT,
            name TEXT,
            artists TEXT,
            explicit INTEGER,
            externalids TEXT,
            islocal INTEGER,
            popularity INTEGER,
            tracknumber INTEGER,
            durationmillis INTEGER
        )",
        [],
    ).unwrap();
}

pub fn register_track(track: &Track) -> Result<()> {
    let conn_guard = TRACKINFO_CONN.lock().unwrap();
    //TODO: Consider adding functionality where "popularity" updates similar to album_info.rs updating images?;
    // Insert some data into the table
    let hashid = track.get_hashid();
    let spotifyid = &track.id;
    let artists = crate::modules::database::artist_info::artist_vec_to_json(&track.artists);
    let explicit: i32 = track.explicit.try_into().unwrap();
    let externalids = track.get_externalids_json();
    let islocal: i32 = track.is_local.try_into().unwrap();
    conn_guard.execute(
        "INSERT OR IGNORE INTO track_info (hashid,spotifyid,name,artists,explicit,externalids,islocal,popularity,tracknumber,durationmillis)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![&hashid,spotifyid,track.name,&artists,&explicit,&externalids,&islocal,&track.popularity,&track.track_number,&track.duration_ms],
    )?;

    Ok(())
}

#[derive(Serialize)]
struct TrackJsonObject {
    hashid: String,
    spotifyid: String,
    name: String,
    artists: String,
    explicit: i64,
    externalids: String,
    islocal: i64,
    popularity: i64,
    tracknumber: i64,
    durationmillis: i64,
}
pub fn get_info_as_json() -> String {
    let conn_guard = TRACKINFO_CONN.lock().unwrap();
    let mut stmt = conn_guard.prepare("SELECT hashid,spotifyid,name,artists,explicit,externalids,islocal,popularity,tracknumber,durationmillis FROM track_info").unwrap();
    let info_iter = stmt.query_map(params![], |row| {
        Ok(TrackJsonObject {
            hashid: row.get(0)?,
            spotifyid: row.get(1)?,
            name: row.get(2)?,
            artists: row.get(3)?,
            explicit: row.get(4)?,
            externalids: row.get(5)?,
            islocal: row.get(6)?,
            popularity: row.get(7)?,
            tracknumber: row.get(8)?,
            durationmillis: row.get(9)?,
        })
    }).unwrap();
    let mut info_list: Vec<TrackJsonObject> = Vec::new();
    for info in info_iter {
        info_list.push(info.unwrap());
    }
    let json_result = serde_json::to_string(&info_list).unwrap();
    return json_result;
}