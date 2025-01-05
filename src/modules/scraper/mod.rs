use std::sync::Mutex;

use chrono::{DateTime, Duration, Timelike, Utc};
use lazy_static::lazy_static;
use reqwest::Client;

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
    actual_scrape_task().await;
}

pub async fn do_task_without_time_check() {
    actual_scrape_task().await;
}

async fn actual_scrape_task() {
    //Scrape
    println!("Begining Spotify Scrape");
    // Get all authentication/refresh token pairs
    let oauth_conn_guard = crate::modules::database::oauth_info::OAUTHINFO_CONN.lock().await;
    let mut stmt = oauth_conn_guard.prepare("SELECT token, refreshtoken FROM oauth_info").unwrap();
    let token_refreshtokens = stmt.query_map([], |row| {
        let token: String = row.get(0)?;
        let refreshtoken: String = row.get(1)?;
        Ok((token, refreshtoken))
    }).unwrap();
    for result in token_refreshtokens {
        match result {
            Ok((token, refreshtoken)) => {
                println!("Handling pair: ({}, {})", &token, &refreshtoken);
                //  Use refresh token to get new authentication token
                let form_data = [
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refreshtoken),
                ];
                let client = Client::new();
                let res = client
                    .post("https://accounts.spotify.com/api/token")
                    .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .form(&form_data)
                    .send().await.unwrap().text().await.unwrap();
                println!("{}", res);
                //  Update database with new authentication token
                //  Pull data from spotify
                //  Add data to database
            }
            Err(e) => {
                println!("Error retrieving token pair: {}", e);
            }
        }
    }
    println!("Done with pairs");
    //Update last scrape time
    let mut last_scrape_time_guard = LAST_SCRAPE_TIME.lock().unwrap();
    *last_scrape_time_guard = Utc::now();
}