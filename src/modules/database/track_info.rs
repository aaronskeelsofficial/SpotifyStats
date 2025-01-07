use std::sync::Mutex;
use crate::modules::scraper::Track;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, Result};

lazy_static! {
    static ref TRACKINFO_CONN: Mutex<Connection> = Mutex::new(Connection::open("assets/track_info.db").unwrap());
}

pub fn register_track(track: &Track) -> Result<()> {
    let conn_guard = TRACKINFO_CONN.lock().unwrap();
    //TODO: Consider adding functionality where "popularity" updates similar to album_info.rs updating images

    // Create a table if it doesn't exist
    conn_guard.execute(
        "CREATE TABLE IF NOT EXISTS track_info
        (
            hashid TEXT PRIMARY KEY,
            name TEXT,
            artists TEXT,
            explicit INTEGER,
            externalids TEXT,
            islocal INTEGER,
            popularity INTEGER,
            tracknumber INTEGER
        )",
        [],
    )?;
    // Insert some data into the table
    let hashid = track.get_hashid();
    let artists = crate::modules::database::artist_info::artist_vec_to_json(&track.artists);
    let explicit: i32 = track.explicit.try_into().unwrap();
    let externalids = track.get_externalids_json();
    let islocal: i32 = track.is_local.try_into().unwrap();
    conn_guard.execute(
        "INSERT OR IGNORE INTO track_info (hashid,name,artists,explicit,externalids,islocal,popularity,tracknumber)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![&hashid,track.name,&artists,&explicit,&externalids,&islocal,track.popularity,track.track_number],
    )?;

    Ok(())
}