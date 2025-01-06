use std::{env, sync::Mutex};

use base64::prelude::*;
use chrono::{DateTime, Duration, Timelike, Utc};
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

lazy_static! {
    static ref LAST_SCRAPE_TIME: Mutex<DateTime<Utc>> = Mutex::new(Utc::now() - chrono::Duration::days(10));
}

pub fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // do_task().await;
        })
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
        let _recently_played_response: RecentlyPlayedResponse = serde_json::from_str(&res).unwrap();
        // println!("Item count: {}", recently_played_response.items.len());
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

    }
    println!("Done with pairs");
    //Update last scrape time
    let mut last_scrape_time_guard = LAST_SCRAPE_TIME.lock().unwrap();
    *last_scrape_time_guard = Utc::now();
}

fn add_data_to_database(rpr: RecentlyPlayedResponse) {
    for pho in rpr.items {
        //First, we handle adding the artists to the artist identification database
        let mut merged_artists_string: String = "".to_string();
        for artist in pho.track.artists {
            merged_artists_string += &artist.name;
        }
        let mut artist_hasher = Sha256::new();
        artist_hasher.update(merged_artists_string);
        let artist_hash_id = artist_hasher.finalize();
        
        //Second, we handle adding the song to the song identification database
        /* Artists often put the same exact fucking song as a single and as an album
        because they are cocksuckers. First, we must make sure they all map to the same
        song or our stats are cooked. We could look at the isrc because it seems to be
        identical in my test across single and album, but I don't trust everyone to
        follow this. So what I SHOULD do is make the uuid something like a sha256 hash
        of the song id + artists id */
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecentlyPlayedResponse {
    href: String,
    limit: i32,
    next: Option<String>,
    cursors: Cursors,
    total: Option<i32>,
    items: Vec<PlayHistoryObject>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cursors {
    after: String,
    before: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayHistoryObject {
    track: Track,
    played_at: String,
    context: Option<Context>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Track {
    album: Album,
    artists: Vec<Artist>,
    available_markets: Vec<String>,
    disc_number: i32,
    duration_ms: i32,
    explicit: bool,
    external_ids: ExternalIds,
    external_urls: ExternalUrls,
    href: String,
    id: String,
    is_playable: Option<bool>,
    //linked_from,
    //restrictions,
    name: String,
    popularity: i32,
    preview_url: Option<String>,
    track_number: i32,
    r#type: String,
    uri: String,
    is_local: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Context {
    r#type: String,
    href: String,
    external_urls: ExternalUrls,
    uri: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Album {
    album_type: String,
    total_tracks: i32,
    available_markets: Vec<String>,
    external_urls: ExternalUrls,
    href: String,
    id: String,
    images: Vec<ImageObject>,
    name: String,
    release_date: String,
    release_date_precision: String,
    //restrictions,
    r#type: String,
    uri: String,
    artists: Vec<Artist>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Artist {
    external_urls: ExternalUrls,
    href: String,
    id: String,
    name: String,
    r#type: String,
    uri: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalIds {
    isrc: Option<String>,
    ean: Option<String>,
    upc: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalUrls {
    spotify: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImageObject {
    url: String,
    height: Option<i32>,
    width: Option<i32>,
}