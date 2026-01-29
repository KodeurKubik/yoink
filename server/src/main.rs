// TODO: replace unwraps with .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

use axum::{Json, Router, http::StatusCode, routing::post};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

const PATH: &str = "./data";
const SERVER: &str = "0.0.0.0:1984";
const PASSWORD: &str = "hello im a password";

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();
pub fn get_db() -> &'static Mutex<Connection> {
    DB.get_or_init(|| Mutex::new(Connection::open(format!("{PATH}/db.sqlite")).unwrap()))
}

#[derive(Serialize, Deserialize, Debug)]
struct DBFiles {
    path: String,
    hash: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    {
        let db = get_db().lock().unwrap();

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (username TEXT, path TEXT, hash TEXT, PRIMARY KEY (username, path));",
        )
        .unwrap();
    }

    let app = Router::new().route("/diff", post(diff));

    let listener = tokio::net::TcpListener::bind(SERVER).await.unwrap();
    println!("Server listening on {SERVER}");
    let _ = axum::serve(listener, app).await;
}

//

#[derive(Deserialize, Debug)]
struct DiffReq {
    root: String,
    username: String,
    password: String,
    files: HashMap<String, u64>,
}
#[derive(Serialize)]
struct DiffRes {
    files: HashMap<String, String>,
}

async fn diff(Json(payload): Json<DiffReq>) -> Result<Json<DiffRes>, StatusCode> {
    if payload.password != PASSWORD {
        return Err(StatusCode::IM_A_TEAPOT);
    }

    let username: String = payload
        .username
        .chars()
        .filter(|c| c.is_alphabetic())
        .collect();

    let oldfiles: Vec<DBFiles> = {
        let db = get_db().lock().unwrap();

        let mut stmt = db
            .prepare("SELECT path, hash FROM users WHERE username = ? AND path LIKE ?")
            .unwrap();

        let u_iter = stmt
            .query_map([&username, &format!("{}%", payload.root)], |row| {
                Ok(DBFiles {
                    path: row.get(0)?,
                    hash: row.get(1)?,
                })
            })
            .unwrap();

        u_iter.collect::<Result<Vec<_>, _>>().unwrap()
    };

    println!("Found DB: {oldfiles:?}");

    let mut updates: HashMap<String, String> = HashMap::with_capacity(payload.files.len());

    for f in payload.files.keys() {
        if let Some(found) = oldfiles.iter().find(|d| d.path == *f) {
            updates.insert(f.to_string(), found.hash.clone());
        } else {
            updates.insert(f.to_string(), "".to_string());
        }
    }

    let res = DiffRes { files: updates };

    Ok(Json(res))
}
