use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use futures_util::StreamExt;
use path_clean::PathClean;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsStr,
    sync::{LazyLock, Mutex, OnceLock},
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

const YOINK_CONFIG_FILE: &str = include_str!(".yoinkconfig");
const PATH: &str = "data";
const MAX_BODY_SIZE: usize = 1_000_000_000;

// dude idk why this is so long lol
static YOINK_IGNORE: LazyLock<Vec<String>> = LazyLock::new(|| {
    std::fs::read_to_string(".yoinkignore")
        .unwrap_or("".to_string())
        .split("\n")
        .filter(|e| !e.is_empty() && !e.starts_with("#"))
        .map(|e| e.to_string())
        .collect()
});

static YOINK_PASS: LazyLock<Vec<String>> = LazyLock::new(|| {
    std::fs::read_to_string(".yoinkpass")
        .unwrap_or("".to_string())
        .split("\n")
        .filter(|e| !e.is_empty() && !e.starts_with("#"))
        .map(|e| e.to_string())
        .collect()
});

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();
pub fn get_db() -> &'static Mutex<Connection> {
    DB.get_or_init(|| Mutex::new(Connection::open(format!("{PATH}/db.sqlite")).unwrap()))
}

#[derive(Clone)]
struct AppState {
    allow_deletion: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct DBFiles {
    path: String,
    hash: String,
}

#[tokio::main]
async fn main() {
    #[cfg(all(feature = "relative", not(debug_assertions)))]
    {
        let exe_path = std::env::current_exe().expect("Failed to get current executable path");

        let exe_dir = exe_path
            .parent()
            .expect("Failed to get executable directory");

        std::env::set_current_dir(exe_dir).expect("Failed to change working directory");
    }

    tracing_subscriber::fmt::init();

    fs::create_dir_all(PATH).await.unwrap();

    let mut yoink_config: HashMap<String, String> = HashMap::with_capacity(2);

    for conf in YOINK_CONFIG_FILE
        .split("\n")
        .filter(|e| !e.is_empty() && !e.starts_with("#"))
        .map(|e| e.to_string())
    {
        if let Some(vals) = conf.split_once("=") {
            yoink_config.insert(vals.0.to_string(), vals.1.to_string());
        }
    }

    let server = yoink_config.get("SERVER").unwrap().to_string();
    let allow_deletion = yoink_config
        .get("ALLOW_DELETION")
        .unwrap_or(&"false".to_string())
        == "true";

    {
        let db = get_db().lock().unwrap();

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (username TEXT, path TEXT, hash TEXT, PRIMARY KEY (username, path));",
        )
        .unwrap();
    }

    let state = AppState { allow_deletion };

    let app = {
        let mut tmp = Router::new()
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .route("/diff/{id}", post(diff))
            .route("/upload/{id}", post(upload));

        if allow_deletion {
            tmp = tmp.route("/delete/{id}", post(deleter));
        }

        tmp.route_layer(middleware::from_fn(auth)).with_state(state)
    };

    let listener = tokio::net::TcpListener::bind(&server).await.unwrap();
    println!("Server listening on {server}");
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
    allow_deletion: bool,
    files: Vec<(String, u64, Option<String>)>,
}

async fn diff(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(payload): Json<DiffReq>,
) -> Result<Json<DiffRes>, StatusCode> {
    let username: String = user_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    let oldfiles: Vec<DBFiles> = {
        let db = get_db()
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut stmt = db
            .prepare("SELECT path, hash FROM users WHERE username = ? AND path LIKE ?;")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let u_iter = stmt
            .query_map([&username, &format!("{}%", payload.root)], |row| {
                Ok(DBFiles {
                    path: row.get(0)?,
                    hash: row.get(1)?,
                })
            })
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        u_iter
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    let mut updates: Vec<(String, u64, Option<String>)> =
        Vec::with_capacity(if state.allow_deletion {
            payload.files.len() + oldfiles.len()
        } else {
            payload.files.len()
        });

    if state.allow_deletion == true {
        for fi in &oldfiles {
            if !payload.files.iter().any(|f| f.0 == fi.path) {
                updates.push((fi.path.clone(), 0u64, Some(fi.hash.clone())));
            }
        }
    }

    for f in payload.files {
        if !YOINK_IGNORE.iter().any(|ig| {
            if ig.starts_with("*") {
                f.0.replace('\\', "/").ends_with(ig)
            } else {
                f.0.replace('\\', "/").contains(ig)
            }
        }) {
            if let Some(found) = oldfiles.iter().find(|d| d.path == f.0) {
                updates.push((f.0, f.1, Some(found.hash.clone())));
            } else {
                updates.push((f.0, f.1, None));
            }
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

    let res = DiffRes {
        allow_deletion: state.allow_deletion,
        files: updates,
    };

    println!("Diff request by {username}");

    Ok(Json(res))
}

//

async fn upload(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    body: Body,
) -> Result<StatusCode, StatusCode> {
    let username: String = user_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    // get user input path, check if it doesn't escape
    let path = String::from_utf8_lossy(
        headers
            .get("X-Path")
            .ok_or(StatusCode::FORBIDDEN)?
            .as_bytes(),
    )
    .to_string()
    .replace(':', "")
    .replace('\\', "/");

    let base_dir = std::path::Path::new(PATH).join(&username);
    let filepath = base_dir.join(&path).clean();
    let filename = filepath
        .file_name()
        .unwrap_or(OsStr::new("unknown"))
        .to_string_lossy()
        .to_string();

    if !filepath.starts_with(&base_dir) {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // if its a folder, stop
    if filepath.is_dir() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // create parent dir
    fs::create_dir_all(&filepath.parent().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // save file
    let mut file = File::create(&filepath)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut stream = body.into_data_stream();
    let mut hasher = blake3::Hasher::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // verify hash
    let xhash = headers
        .get("X-Hash")
        .ok_or(StatusCode::FORBIDDEN)?
        .to_str()
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let hash = hasher.finalize().to_hex().to_string();

    // save to db
    {
        let db = get_db().lock().unwrap();

        db.execute(
            "INSERT INTO users (username, path, hash) VALUES(?, ?, ?) ON CONFLICT(username, path) DO UPDATE SET hash=?;",
            (&username, &path, &hash, &hash),
        ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if hash != xhash {
        // uh oh
        // tbh idk what to do, lets just keep file and send specific error to client
        return Err(StatusCode::REQUEST_TIMEOUT);
    }

    println!("Successfully uploaded {filename} for user {username}");

    Ok(StatusCode::OK)
}

//

#[derive(Deserialize)]
struct DeleteReq {
    files: Vec<String>,
}

async fn deleter(
    Path(user_id): Path<String>,
    Json(payload): Json<DeleteReq>,
) -> Result<StatusCode, StatusCode> {
    let username: String = user_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    let base_dir = std::path::Path::new(PATH).join(&username);

    for path in payload
        .files
        .iter()
        .map(|p| p.replace(':', "").replace('\\', "/"))
    {
        let filepath = base_dir.join(&path).clean();
        let filename = filepath
            .file_name()
            .unwrap_or(OsStr::new("unknown"))
            .to_string_lossy()
            .to_string();

        if !filepath.starts_with(&base_dir) {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        // if its a folder, stop
        if filepath.is_dir() {
            return Err(StatusCode::BAD_REQUEST);
        }

        delete_element(&filepath)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        {
            let db = get_db().lock().unwrap();

            // save to db
            db.execute(
                "DELETE FROM users WHERE username=? AND path=?;",
                (&username, &path),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }

        println!("Successfully deleted {filename} for user {username}");
    }

    Ok(StatusCode::OK)
}

//

async fn auth(
    headers: HeaderMap,
    Path(user_id): Path<String>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let xpwd = headers
        .get("X-Auth")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let username: String = user_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    let valid = YOINK_PASS.iter().any(|pwd| {
        if let Some(u_pwd) = pwd.split_once(": ") {
            return u_pwd.0 == &username && u_pwd.1 == xpwd;
        } else {
            return pwd == xpwd;
        }
    });

    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let response = next.run(request).await;
    Ok(response)
}

//

async fn delete_element(filepath: &std::path::PathBuf) -> tokio::io::Result<()> {
    let mut anc = filepath.ancestors();
    let mut last: Option<&std::path::Path> = None;
    let mut prev_name = filepath.file_name();

    loop {
        if let Some(got) = anc.next() {
            if got.is_dir() {
                let mut read = fs::read_dir(&got).await?;

                let first_ent = read.next_entry().await?;
                let empty = {
                    if let Some(ent) = first_ent {
                        Some(ent.file_name().as_os_str()) == prev_name
                            && read.next_entry().await?.is_none()
                    } else {
                        false
                    }
                };

                if empty {
                    last = Some(got);
                    prev_name = got.file_name();
                } else {
                    if let Some(path) = last {
                        // delete n-th parent folder
                        fs::remove_dir_all(path).await?;
                    } else {
                        // delete file
                        fs::remove_file(&filepath).await?;
                    }
                    return Ok(());
                }
            }
        } else {
            return Ok(());
        }
    }
}
