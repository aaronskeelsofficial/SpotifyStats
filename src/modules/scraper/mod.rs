use std::{env, sync::Mutex};

use base64::prelude::*;
use chrono::{DateTime, Duration, Timelike, Utc};
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
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            loop {
                do_task_without_time_check().await;
                let average_song_duration = 3;
                let maximum_songs_per_request = 50;
                let total_runtime = average_song_duration*maximum_songs_per_request;
                //We sleep for 2.5 hours because if you listened nonstop to average length music
                // that's how long we could wait for a queue of 50 (because spotify only stores last 50)
                sleep(std::time::Duration::from_secs(60*total_runtime)).await;
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
        actual_scrape_task();
    });
    // actual_scrape_task();
}

pub async fn do_task_without_time_check() {
    tokio::task::block_in_place(|| {
        actual_scrape_task();
    });
    // actual_scrape_task();
}

fn actual_scrape_task() {
    //Scrape
    println!("Begining Spotify Scrape");
    // Cleanse all expired authentication/refresh token pairs
    crate::modules::database::oauth_info::cleanse_invalid_info();
    // Get all authentication/refresh token pairs
    let oauth_conn_guard = crate::modules::database::oauth_info::OAUTHINFO_CONN.lock().unwrap();
    let info: Vec<(String, String, String)> = {
        let stmt = &mut oauth_conn_guard.prepare("SELECT uuid,token,refreshtoken FROM oauth_info").unwrap();
        stmt.query_map([], |row| {
            let uuid: String = row.get(0)?;
            let token: String = row.get(1)?;
            let refreshtoken: String = row.get(2)?;
            Ok((uuid, token, refreshtoken))
        })
        .unwrap()
        .filter_map(|result| result.ok())  // Filter out any errors
        .map(|(uuid, token, refreshtoken)| {
            // Clone each String value
            (uuid.clone(), token.clone(), refreshtoken.clone())
        })
        .collect()  // Collect into a Vec
    };
    drop(oauth_conn_guard);
    for (uuid,token,refreshtoken) in info {
        println!("Handling pair: ({}, {})", &token, &refreshtoken);
        //  Use refresh token to get new authentication token
        println!("Using refresh token to get new authentication token");
        let form_data = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &refreshtoken),
        ];
        let auth_string = "Basic ".to_string() + &BASE64_STANDARD.encode(env::var("SPOTIFY_CLIENT_ID").unwrap() + &":".to_string() + &env::var("SPOTIFY_CLIENT_SECRET").unwrap());
        let client = Client::new();
        let res: String = tokio::runtime::Runtime::new().unwrap().block_on(async {
            client
                .post("https://accounts.spotify.com/api/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("Authorization", auth_string)
                .form(&form_data)
                .send().await.unwrap().text().await.unwrap()
        });
        println!("{}", res);
        let v: serde_json::Value = serde_json::from_str(&res).unwrap();
        //  Update database with new authentication token
        println!("Updating database with new auth token");
        let token = v["access_token"].to_string().replace("\"", "");
        let token_type = v["token_type"].to_string().replace("\"", "");
        let expires_timestamp = chrono::Utc::now() + Duration::seconds(v["expires_in"].as_i64().unwrap());
        let mut refresh_token = refreshtoken.clone();
        if v.get("refresh_token").is_some() {
            refresh_token = v.get("refresh_token").unwrap().to_string();
        }
        crate::modules::database::oauth_info::set_token_info(&uuid, &token, &token_type, &expires_timestamp, &refresh_token);
        //  Pull data from spotify
        println!("Pulling data from spotify");
        let form_data = [
            ("limit", 50),
        ];
        let auth_string = "Bearer ".to_string() + &token;
        //   Manually do a first ping, and then have a custom secondary rolling ping
        println!("Pinging https://api.spotify.com/v1/me/player/recently-played");
        let res: String = tokio::runtime::Runtime::new().unwrap().block_on(async {
            client
                .get("https://api.spotify.com/v1/me/player/recently-played")
                .header("Authorization", &auth_string)
                .query(&form_data)
                .send().await.unwrap().text().await.unwrap()
        });
        std::fs::write("output.txt", &res).unwrap();
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
        add_data_to_database(&uuid, &recently_played_response);
    }
    println!("Done with pairs");
    //Update last scrape time
    let mut last_scrape_time_guard = LAST_SCRAPE_TIME.lock().unwrap();
    *last_scrape_time_guard = Utc::now();
}

fn add_data_to_database(uuid: &String, rpr: &RecentlyPlayedResponse) {
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
        crate::modules::database::listen_history_info::register_listen(uuid, &pho).unwrap();
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