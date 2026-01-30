// TODO: replace unwraps with .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

use axum::{
    Json, Router,
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use tokio::{fs::File, io::AsyncWriteExt};

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

    let app = Router::new()
        .route("/diff/{id}", post(diff))
        .route("/upload/{id}", post(upload));

    let listener = tokio::net::TcpListener::bind(SERVER).await.unwrap();
    println!("Server listening on {SERVER}");
    let _ = axum::serve(listener, app).await;
}

//

#[derive(Deserialize)]
struct DiffReq {
    root: String,
    files: Vec<(String, u64)>,
}
#[derive(Serialize)]
struct DiffRes {
    files: Vec<(String, u64, Option<String>)>,
}

async fn diff(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(payload): Json<DiffReq>,
) -> Result<Json<DiffRes>, StatusCode> {
    let pwd = headers
        .get("x-auth")
        .ok_or(StatusCode::FORBIDDEN)?
        .to_str()
        .map_err(|_| StatusCode::FORBIDDEN)?;

    if pwd != PASSWORD {
        return Err(StatusCode::FORBIDDEN);
    }

    let username: String = user_id.chars().filter(|c| c.is_alphabetic()).collect();

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

    let mut updates: Vec<(String, u64, Option<String>)> = Vec::with_capacity(payload.files.len());

    for f in payload.files {
        if let Some(found) = oldfiles.iter().find(|d| d.path == f.0) {
            updates.push((f.0, f.1, Some(found.hash.clone())));
        } else {
            updates.push((f.0, f.1, None));
        }
    }

    updates.sort_by(|a, b| {
        if a.2.is_none() && !b.2.is_none() {
            return std::cmp::Ordering::Less;
        } else if !a.2.is_none() && b.2.is_none() {
            return std::cmp::Ordering::Greater;
        }

        a.1.cmp(&b.1)
    });

    let res = DiffRes { files: updates };

    Ok(Json(res))
}

//

async fn upload(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Result<(), StatusCode> {
    let pwd = headers
        .get("x-auth")
        .ok_or(StatusCode::FORBIDDEN)?
        .to_str()
        .map_err(|_| StatusCode::FORBIDDEN)?;

    if pwd != PASSWORD {
        return Err(StatusCode::FORBIDDEN);
    }

    let username: String = user_id.chars().filter(|c| c.is_alphabetic()).collect();

    let base_dir = std::path::Path::new(PATH).join(&username);

    tokio::fs::create_dir_all(&base_dir)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let filepath = base_dir.join("uploaded_file");

    let mut file = File::create(&filepath)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    file.write_all(&body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Ok(())
    Err(StatusCode::IM_A_TEAPOT)
}
