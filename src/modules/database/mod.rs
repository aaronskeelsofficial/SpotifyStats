use std::path::Path;

pub mod oauth_info;
pub mod profile_info;
pub mod logintoken_info;
pub mod album_info;
pub mod artist_info;
pub mod track_info;
pub mod listen_history_info;

pub fn first_init_if_necessary() {
    std::fs::create_dir_all(Path::new("assets").join(Path::new("db"))).unwrap();
    album_info::first_init_if_necessary();
    artist_info::first_init_if_necessary();
    listen_history_info::first_init_if_necessary();
    logintoken_info::first_init_if_necessary();
    oauth_info::first_init_if_necessary();
    profile_info::first_init_if_necessary();
    track_info::first_init_if_necessary();
}

/* oauth_info.db
ip TEXT PRIMARY KEY,
code TEXT,
token TEXT,
tokentype TEXT,
expirestimestamp TEXT,  (rfc3339 format)
refreshtoken TEXT
 */

/* profile_info.db
uuid TEXT PRIMARY KEY
username TEXT NOT NULL
hashed_password TEXT NOT NULL
salt TEXT NOT NULL
*/

/* logintoken_info.db
token TEXT PRIMARY KEY,
uuid TEXT NOT NULL,
lastusedtimestamp TEXT NOT NULL
 */

/* album_info.db
spotifyid TEXT
name TEXT
artists TEXT    (json array of artist ids)
images TEXT     (json array of image objects (height,url,width))
releasedate TEXT    (YYYY-MM-DD or YYYY-MM or YYYY depending on precision)
releasedateprecision TEXT
totaltracks INT UNSIGNED
*/

/* artist_info.db
spotifyid TEXT
name TEXT
*/

/* track_info.db
hashid TEXT     (SHA256 hashed string of name + comma + comma separated artist ids)
name TEXT
artists TEXT    (json array of artist ids)
explicit INTEGER    (really a bool)
externalids TEXT
islocal INTEGER     (really a bool)
popularity INTEGER
tracknumber INTEGER
*/

/* listen_history_info.db
uuid TEXT   (user account uuid)
trackhashid TEXT
artists TEXT    (json array of artist ids)
albumspotifyid TEXT
timestamp TEXT
*/