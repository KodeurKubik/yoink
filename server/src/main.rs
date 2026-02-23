#[cfg(feature = "self_https")]
use aes_gcm::{Aes256Gcm, KeyInit, aead::stream::DecryptorBE32};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
#[cfg(feature = "self_https")]
use base64::{Engine, prelude::BASE64_STANDARD};
use dashmap::DashMap;
use futures_util::StreamExt;
use path_clean::PathClean;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsStr,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

const YOINK_CONFIG_FILE: &str = include_str!(".yoinkconfig");
const PATH: &str = "data";
const MAX_BODY_SIZE: usize = 1_000_000_000;
const RATELIMITER_MAXFAILS: u32 = 2;
const RATELIMITER_PERSEC: u64 = 15;

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
    failure_counts: Arc<DashMap<IpAddr, (u32, Instant)>>,
    #[cfg(feature = "self_https")]
    https_key: aes_gcm::Aes256Gcm,
}

impl AppState {
    pub fn is_limited(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.failure_counts.get(&ip) {
            let (count, reset_at) = *entry;
            count >= RATELIMITER_MAXFAILS && Instant::now() < reset_at
        } else {
            false
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();

        self.failure_counts
            .entry(ip)
            .and_modify(|(count, reset_at)| {
                if now >= *reset_at {
                    *count = 1;
                    *reset_at =
                        now + Duration::from_secs(RATELIMITER_PERSEC) / RATELIMITER_MAXFAILS;
                } else {
                    *count += 1
                }
            })
            .or_insert((
                1,
                now + Duration::from_secs(RATELIMITER_PERSEC) / RATELIMITER_MAXFAILS,
            ));
    }
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

    #[cfg(feature = "self_https")]
    let https_key = {
        yoink_config
            .get("HTTPS_KEY")
            .map(|v| {
                let bytes = BASE64_STANDARD
                    .decode(v)
                    .expect("Could not parse HTTPS_KEY");

                let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&bytes).to_owned();
                let cipher = aes_gcm::Aes256Gcm::new(&key);
                cipher
            })
            .unwrap_or_else(|| {
                eprintln!("NO HTTPS_KEY SPECIFIED!");
                eprintln!("If the self_https flag is enabled, you should compile with the HTTPS_KEY config. Here's a randomly generated key:");

                let key = aes_gcm::Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
                eprintln!("{}\n", BASE64_STANDARD.encode(key));

                let cipher = aes_gcm::Aes256Gcm::new(&key);
                cipher
            })
    };

    let state = AppState {
        allow_deletion,
        #[cfg(feature = "self_https")]
        https_key: https_key,
        failure_counts: Arc::new(DashMap::new()),
    };

    let app = {
        let mut tmp = Router::new()
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .route("/test/{id}", get(tester))
            .route("/diff/{id}", post(diff))
            .route("/upload/{id}", post(upload));

        if allow_deletion {
            tmp = tmp.route("/delete/{id}", post(deleter));
        }

        tmp.route_layer(middleware::from_fn_with_state(state.clone(), auth))
            .with_state(state)
    };

    #[cfg(feature = "self_https")]
    println!("Server listening on {server} - with encryption layer");
    #[cfg(not(feature = "self_https"))]
    println!("Server listening on {server}");

    let listener = tokio::net::TcpListener::bind(&server).await.unwrap();
    let _ = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await;
}

//

async fn tester() -> &'static str {
    "Your account works."
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

#[cfg(feature = "self_https")]
async fn diff(
    headers: HeaderMap,
    state: State<AppState>,
    user_id: Path<String>,
    body: Bytes,
) -> Result<Bytes, StatusCode> {
    let nonce = get_header_nonce(&headers)?;

    let data = decrypt_str_to_vec(
        &String::from_utf8_lossy(&body).to_string(),
        &state.https_key,
        &nonce,
    )?;

    let payload: DiffReq = serde_json::from_slice(&data).map_err(|_| StatusCode::BAD_REQUEST)?;

    diff_handler(headers, state, user_id, Json(payload)).await
}

#[cfg(not(feature = "self_https"))]
async fn diff(
    state: State<AppState>,
    user_id: Path<String>,
    payload: Json<DiffReq>,
) -> Result<Bytes, StatusCode> {
    diff_handler(state, user_id, payload).await
}

async fn diff_handler(
    #[cfg(feature = "self_https")] headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(payload): Json<DiffReq>,
) -> Result<Bytes, StatusCode> {
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

    #[cfg(feature = "self_https")]
    let res = {
        let res_raw = serde_json::to_string(&DiffRes {
            allow_deletion: state.allow_deletion,
            files: updates,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let nonce = get_header_nonce(&headers)?;

        encrypt_https(&res_raw, &state.https_key, &nonce)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    #[cfg(not(feature = "self_https"))]
    let res = serde_json::to_vec(&DiffRes {
        allow_deletion: state.allow_deletion,
        files: updates,
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("Diff request by {username}");

    Ok(res.into())
}

//

#[cfg(feature = "self_https")]
async fn upload(
    headers: HeaderMap,
    state: State<AppState>,
    user_id: Path<String>,
    body: Body,
) -> Result<StatusCode, StatusCode> {
    upload_handler(headers, state, user_id, body).await
}

#[cfg(not(feature = "self_https"))]
async fn upload(
    headers: HeaderMap,
    user_id: Path<String>,
    body: Body,
) -> Result<StatusCode, StatusCode> {
    upload_handler(headers, user_id, body).await
}

async fn upload_handler(
    headers: HeaderMap,
    #[cfg(feature = "self_https")] state: State<AppState>,
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

    let mut hasher = blake3::Hasher::new();
    let mut stream = body.into_data_stream();

    #[cfg(feature = "self_https")]
    {
        let streamnonce = get_header_nonce_stream(&headers)?;
        let mut decryptor = Some(DecryptorBE32::<Aes256Gcm>::from_aead(
            state.https_key.clone(),
            &streamnonce,
        ));

        let mut leftovers = Vec::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
            leftovers.extend_from_slice(&chunk);

            while leftovers.len() > 65536 + 16 {
                let plaintext = decryptor
                    .as_mut()
                    .ok_or(StatusCode::BAD_REQUEST)?
                    .decrypt_next(&leftovers[..65536 + 16])
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                file.write_all(&plaintext)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                hasher.update(&plaintext);
                leftovers.drain(..65536 + 16);
            }
        }

        let plaintext = decryptor
            .take()
            .ok_or(StatusCode::BAD_REQUEST)?
            .decrypt_last(&leftovers[..])
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        file.write_all(&plaintext)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        hasher.update(&plaintext);
    }

    #[cfg(not(feature = "self_https"))]
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        #[cfg(feature = "self_https")]
        let plaintext =
            decrypt_https(&chunk, &state.https_key, &nonce).map_err(|_| StatusCode::BAD_REQUEST)?;

        #[cfg(not(feature = "self_https"))]
        let plaintext = chunk;

        hasher.update(&plaintext);
        file.write_all(&plaintext)
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
        eprintln!(
            "File {filename} from user {username} did not match hash, keeping file as backup"
        );
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

#[cfg(feature = "self_https")]
async fn deleter(
    headers: HeaderMap,
    state: State<AppState>,
    user_id: Path<String>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let nonce = get_header_nonce(&headers)?;

    let data = decrypt_str_to_vec(
        &String::from_utf8_lossy(&body).to_string(),
        &state.https_key,
        &nonce,
    )?;

    let payload: DeleteReq = serde_json::from_slice(&data).map_err(|_| StatusCode::BAD_REQUEST)?;

    deleter_handler(user_id, Json(payload)).await
}

#[cfg(not(feature = "self_https"))]
async fn deleter(
    user_id: Path<String>,
    payload: Json<DeleteReq>,
) -> Result<StatusCode, StatusCode> {
    deleter_handler(user_id, payload).await
}

async fn deleter_handler(
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = addr.ip();

    if state.is_limited(ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    #[cfg(feature = "self_https")]
    let nonce = get_header_nonce(&headers)?;

    #[allow(unused_mut)]
    let mut xpwd = headers
        .get("X-Auth")
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string();

    #[cfg(feature = "self_https")]
    {
        xpwd = decrypt_str_to_str(&xpwd, &state.https_key, &nonce)?;
    }

    let username: String = user_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    let valid = YOINK_PASS.iter().any(|pwd| {
        if let Some(u_pwd) = pwd.split_once(": ") {
            return u_pwd.0 == &username && u_pwd.1 == &xpwd;
        } else {
            return pwd == &xpwd;
        }
    });

    if !valid {
        println!("Password not valid!");

        state.record_failure(ip);
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

//

#[cfg(feature = "self_https")]
fn get_header_nonce_stream(
    headers: &HeaderMap,
) -> Result<aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U7>, StatusCode> {
    let nonce_header_bytes = headers
        .get("X-Nonce-Stream")
        .ok_or(StatusCode::BAD_REQUEST)?
        .as_bytes();

    let nonce_bytes = BASE64_STANDARD
        .decode(nonce_header_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if nonce_bytes.len() != 7 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let nonce = aes_gcm::Nonce::clone_from_slice(&nonce_bytes);
    Ok(nonce)
}

#[cfg(feature = "self_https")]
fn get_header_nonce(
    headers: &HeaderMap,
) -> Result<aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U12>, StatusCode> {
    let nonce_header_bytes = headers
        .get("X-Nonce")
        .ok_or(StatusCode::BAD_REQUEST)?
        .as_bytes();

    let nonce_bytes = BASE64_STANDARD
        .decode(nonce_header_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if nonce_bytes.len() != 12 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let nonce = aes_gcm::Nonce::clone_from_slice(&nonce_bytes);
    Ok(nonce)
}

#[cfg(feature = "self_https")]
fn decrypt_str_to_vec(
    bytes: &String,
    cipher: &aes_gcm::Aes256Gcm,
    nonce: &aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U12>,
) -> Result<Vec<u8>, StatusCode> {
    let decoded = BASE64_STANDARD
        .decode(bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let decrypted =
        decrypt_https(&decoded, &cipher, &nonce).map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(decrypted)
}

#[cfg(feature = "self_https")]
fn decrypt_str_to_str(
    bytes: &String,
    cipher: &aes_gcm::Aes256Gcm,
    nonce: &aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U12>,
) -> Result<String, StatusCode> {
    Ok(String::from_utf8_lossy(&decrypt_str_to_vec(bytes, cipher, nonce)?).to_string())
}

//

#[cfg(feature = "self_https")]
fn encrypt_https(
    body: &str,
    cipher: &aes_gcm::Aes256Gcm,
    nonce: &aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U12>,
) -> Result<Vec<u8>, aes_gcm::Error> {
    use aes_gcm::aead::Aead;

    let dec = cipher.encrypt(nonce, body.as_bytes())?;
    Ok(dec)
}

#[cfg(feature = "self_https")]
fn decrypt_https(
    body: &[u8],
    cipher: &aes_gcm::Aes256Gcm,
    nonce: &aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U12>,
) -> Result<Vec<u8>, aes_gcm::Error> {
    use aes_gcm::aead::Aead;

    let dec = cipher.decrypt(nonce, body)?;
    Ok(dec)
}
