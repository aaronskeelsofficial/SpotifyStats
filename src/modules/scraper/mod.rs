use std::{collections::HashSet, sync::Mutex};

use chrono::{DateTime, Duration, Local, Timelike, Utc};
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::time::sleep;

use super::database::artist_info;

lazy_static! {
    static ref LAST_SCRAPE_TIME: Mutex<DateTime<Utc>> = Mutex::new(Utc::now() - chrono::Duration::days(10));
}

pub fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            loop {
                let average_song_duration = 3;
                let maximum_songs_per_request = 50;
                let total_runtime: u64 = average_song_duration*maximum_songs_per_request;
                //We sleep for 2.5 hours because if you listened nonstop to average length music
                // that's how long we could wait for a queue of 50 (because spotify only stores last 50)
                let new_time = Local::now() + chrono::Duration::minutes(total_runtime.try_into().unwrap());
                println!("Next scrape @: {}", new_time.to_string());
                // do_task_without_time_check().await;
                sleep(std::time::Duration::from_secs(60*total_runtime)).await;
                do_task_without_time_check().await;
            }
        });
}

pub async fn do_task_with_time_check() {
    //Check if it is after 11:55
    let now = chrono::Utc::now();
    if now.hour() < 23 || now.minute() < 55 {
        return;
    }
    //Check time since last scrape >= 10 mins
    let last_scrape_time_guard = LAST_SCRAPE_TIME.lock().unwrap();
    if Utc::now() - *last_scrape_time_guard < Duration::minutes(10) {
        return;
    }
    tokio::task::block_in_place(|| {
        actual_scrape_task_for_all();
    });
    // actual_scrape_task();
}

pub async fn do_task_without_time_check() {
    tokio::task::block_in_place(|| {
        actual_scrape_task_for_all();
    });
    // actual_scrape_task();
}

fn actual_scrape_task_for_all() {
    //Scrape
    println!("Begining Spotify Scrape");
    // Revalidate all expired authentication/refresh token pairs
    println!("Revalidating tokens");
    crate::modules::database::oauth_info::revalidate_invalid_info();
    // Get all authentication/refresh token pairs
    let oauth_conn_guard = crate::modules::database::oauth_info::OAUTHINFO_CONN.lock().unwrap();
    let info: Vec<(String,String,String)> = {
        let stmt = &mut oauth_conn_guard.prepare("SELECT spotifyid,displayname,token FROM oauth_info").unwrap();
        stmt.query_map([], |row| {
            let spotifyid: String = row.get(0)?;
            let displayname: String = row.get(1)?;
            let token: String = row.get(2)?;
            Ok((spotifyid,displayname,token))
        })
        .unwrap()
        .filter_map(|result| result.ok())  // Filter out any errors
        .map(|(spotifyid,displayname,token)| {
            // Clone each String value
            (spotifyid.clone(),displayname.clone(),token.clone())
        })
        .collect()  // Collect into a Vec
    };
    drop(oauth_conn_guard);
    //
    let mut handled_spotifyid: HashSet<String> = HashSet::new();
    for (spotifyid,displayname,token) in info {
        if !handled_spotifyid.contains(&spotifyid) {
            scrape(&spotifyid,&displayname,&token);
            handled_spotifyid.insert(spotifyid.clone());
        }
    }
    println!("Done with scrape");
    // //Update last scrape time
    // let mut last_scrape_time_guard = LAST_SCRAPE_TIME.lock().unwrap();
    // *last_scrape_time_guard = Utc::now();
}

pub fn scrape(spotifyid: &String, displayname: &String, token: &String) {
    println!("Handling Spotify scrape for: {} ({})", &spotifyid, displayname);
        //  Pull data from spotify
        let form_data = [
            ("limit", 50),
        ];
        let auth_string = "Bearer ".to_string() + &token;
        let client = Client::new();
        //   Manually do a first ping, and then have a custom secondary rolling ping
        println!("Pinging https://api.spotify.com/v1/me/player/recently-played");
        let res: String = tokio::runtime::Runtime::new().unwrap().block_on(async {
            client
                .get("https://api.spotify.com/v1/me/player/recently-played")
                .header("Authorization", &auth_string)
                .query(&form_data)
                .send().await.unwrap().text().await.unwrap()
        });
        std::fs::write(format!("output_{}.txt",spotifyid.get(0..5).unwrap()), &res).unwrap();
        let recently_played_response: RecentlyPlayedResponse = serde_json::from_str(&res).unwrap();
        //   Now do the custom rolling ping
        //   EDIT: Spotify only provides the last 50 songs. No need for a rolling ping.
        // let mut counter = 1;
        // while recently_played_response.next.is_some() {
        //     let url = recently_played_response.next.as_ref().unwrap();
        //     println!("Pinging({}): {}", counter, url);
        //     let res: String = tokio::runtime::Runtime::new().unwrap().block_on(async {
        //         client
        //             .get(url)
        //             .header("Authorization", &auth_string)
        //             .send().await.unwrap().text().await.unwrap()
        //     });
        //     std::fs::write(format!("output{}.txt", counter), &res).unwrap();
        //     let last_recently_played_response: RecentlyPlayedResponse = serde_json::from_str(&res).unwrap();
        //     recently_played_response.items.extend(last_recently_played_response.items.iter().cloned());
        //     recently_played_response.next = last_recently_played_response.next;
        //     counter += 1;
        // }
        //  Add data to database
        add_data_to_database(&spotifyid, &recently_played_response);
}

fn add_data_to_database(spotifyid: &String, rpr: &RecentlyPlayedResponse) {
    println!("Adding data to database");
    for pho in &rpr.items {
        //Add artists
        for artist in &pho.track.artists {
            crate::modules::database::artist_info::register_artist(artist).unwrap();
        }
        //Add album (note: even singles appear as albums so make sure more than 1 song)
        if &pho.track.album.total_tracks >= &2 {
            crate::modules::database::album_info::register_album(&pho.track.album).unwrap();
        }
        //Now, we handle adding the song to the track identification database
        /* Artists often put the same exact fucking song as a single and as an album
        because they are cocksuckers. First, we must make sure they all map to the same
        song or our stats are cooked. We could look at the isrc because it seems to be
        identical in my test across single and album, but I don't trust everyone to
        follow this. So what I SHOULD do is make the uuid something like a sha256 hash
        of the song id + artists id */
        crate::modules::database::track_info::register_track(&pho.track).unwrap();
        //Add listen
        crate::modules::database::listen_history_info::register_listen(spotifyid, &pho).unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecentlyPlayedResponse {
    pub href: String,
    pub limit: i32,
    pub next: Option<String>,
    pub cursors: Cursors,
    pub total: Option<i32>,
    pub items: Vec<PlayHistoryObject>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cursors {
    pub after: String,
    pub before: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayHistoryObject {
    pub track: Track,
    pub played_at: String,
    pub context: Option<Context>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Track {
    pub album: Album,
    pub artists: Vec<Artist>,
    pub available_markets: Vec<String>,
    pub disc_number: i32,
    pub duration_ms: i32,
    pub explicit: bool,
    pub external_ids: ExternalIds,
    pub external_urls: ExternalUrls,
    pub href: String,
    pub id: String,
    pub is_playable: Option<bool>,
    //linked_from,
    //restrictions,
    pub name: String,
    pub popularity: i32,
    pub preview_url: Option<String>,
    pub track_number: i32,
    pub r#type: String,
    pub uri: String,
    pub is_local: bool,
}
impl Track {
    pub fn get_externalids_json(&self) -> String {
        let externalids_json = serde_json::to_string(&self.external_ids).unwrap();
        return externalids_json;
    }
    pub fn get_hashid(&self) -> String {
        let name_portion = &self.name;
        let comma_sep_artist_portion = &artist_info::artist_vec_to_comma_sep_string(&self.artists);
        let combined = format!("{},{}", name_portion, comma_sep_artist_portion);
        let mut sha = sha2::Sha256::new();
        sha.update(combined);
        let sha_output = sha.finalize();
        let hex_string = hex::encode(sha_output);
        return hex_string;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Context {
    pub r#type: String,
    pub href: String,
    pub external_urls: ExternalUrls,
    pub uri: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Album {
    pub album_type: String,
    pub total_tracks: i32,
    pub available_markets: Vec<String>,
    pub external_urls: ExternalUrls,
    pub href: String,
    pub id: String,
    pub images: Vec<ImageObject>,
    pub name: String,
    pub release_date: String,
    pub release_date_precision: String,
    //restrictions,
    pub r#type: String,
    pub uri: String,
    pub artists: Vec<Artist>,
}
impl Album {
    pub fn get_images_json(&self) -> String {
        let images_json = serde_json::to_string(&self.images).unwrap();
        return images_json;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Artist {
    pub external_urls: ExternalUrls,
    pub href: String,
    pub id: String,
    pub name: String,
    pub r#type: String,
    pub uri: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalIds {
    pub isrc: Option<String>,
    pub ean: Option<String>,
    pub upc: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalUrls {
    pub spotify: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImageObject {
    pub url: String,
    pub height: Option<i32>,
    pub width: Option<i32>,
}