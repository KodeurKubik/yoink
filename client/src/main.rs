// dont open any window on windows
#![cfg_attr(
    all(not(debug_assertions), not(feature = "log"), target_os = "windows"),
    windows_subsystem = "windows"
)]

#[cfg(feature = "self_https")]
use aes_gcm::aead::stream::EncryptorBE32;
#[cfg(feature = "self_https")]
use aes_gcm::{Aes256Gcm, KeyInit, aead};
#[cfg(feature = "self_https")]
use base64::{Engine, prelude::BASE64_STANDARD};
#[cfg(feature = "self_https")]
use rand::RngExt;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reqwest::{
    blocking::{Body, Client},
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "self_https")]
use std::io::Read;
use std::{
    collections::HashMap,
    fs::{File, exists, read_dir},
    io::BufReader,
    path::PathBuf,
    sync::Mutex,
    time::Duration,
};

const YOINK_CONFIG_FILE: &str = include_str!(".yoinkconfig");
const UNKNOWN_FILE_SIZE: u64 = 1_000_000_000;
const MULTI_THREAD_COUNT: usize = 5;
const MAX_PATH_NOT_AVAILABLE_RETRIES: usize = 15;
const PATH_NOT_AVAILABLE_DELAY: Duration = Duration::from_secs(3);

fn main() {
    #[cfg(all(feature = "relative", not(debug_assertions)))]
    {
        let exe_path = std::env::current_exe().expect("Failed to get current executable path");

        let exe_dir = exe_path
            .parent()
            .expect("Failed to get executable directory");

        std::env::set_current_dir(exe_dir).expect("Failed to change working directory");
    }

    let mut yoink_config: HashMap<String, String> = HashMap::with_capacity(4);

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
    let password = yoink_config.get("PASSWORD").unwrap().to_string();
    let mut paths = yoink_config
        .get("PATH")
        .unwrap()
        .split(",")
        .map(|e| e.to_string())
        .collect::<Vec<String>>();
    let username = yoink_config
        .get("USERNAME")
        .unwrap_or(&"unknown".to_string())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>();

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
            .expect("Please specify a HTTPS_KEY in the config if self_https flag is enabled")
    };

    // http client
    let mut headers = HeaderMap::new();

    #[cfg(feature = "self_https")]
    let mut https_nonce = aes_gcm::Nonce::from([0u8; 12]);

    #[cfg(not(feature = "self_https"))]
    headers.insert("X-Auth", HeaderValue::from_str(&password).unwrap());

    let client = Client::builder().build().unwrap();

    // magic

    let mut waitlist: Vec<String> = Vec::with_capacity(paths.len());
    let mut retries: usize = 0;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(MULTI_THREAD_COUNT)
        .build()
        .unwrap();

    let mut del: Vec<String> = Vec::new();

    while let Some(path) = paths.pop() {
        match exists(&path) {
            Ok(false) => {
                #[cfg(feature = "log")]
                println!("Waiting for path {path}");
                waitlist.push(path);
            }
            Ok(true) => {
                let mut files: Vec<(String, u64)> = Vec::with_capacity(1_000);
                walk_dir(&mut files, PathBuf::from(&path));

                #[cfg(feature = "self_https")]
                new_nonce(&mut headers, &mut https_nonce, &password, &https_key);

                let diff_req_raw = DiffReq {
                    root: path,
                    files: files.clone(),
                };

                #[cfg(feature = "self_https")]
                let diff_req = BASE64_STANDARD.encode(
                    encrypt_https(
                        &serde_json::to_string(&diff_req_raw).unwrap(),
                        &https_key,
                        &https_nonce,
                    )
                    .unwrap(),
                );

                #[cfg(not(feature = "self_https"))]
                let diff_req = serde_json::to_vec(&diff_req_raw).unwrap();

                #[cfg(feature = "log")]
                println!("Got {} files to diff", files.len());

                let diff_res_raw = client
                    .post(format!("{server}/diff/{username}"))
                    .headers(headers.clone())
                    .body(diff_req)
                    .send()
                    .unwrap()
                    .bytes()
                    .unwrap()
                    .to_vec();

                #[cfg(feature = "self_https")]
                let diff_res: DiffRes = {
                    let decrypted = decrypt_https(&diff_res_raw, &https_key, &https_nonce).unwrap();
                    serde_json::from_slice(&decrypted).unwrap()
                };

                #[cfg(not(feature = "self_https"))]
                let diff_res: DiffRes = serde_json::from_slice(&diff_res_raw).unwrap();

                let del_temp: Mutex<Vec<String>> = Mutex::new(Vec::new());

                pool.install(|| {
                    diff_res.files.into_par_iter().for_each(|f| {
                        // f.0 file path, f.1 file hash
                        if files.contains(&(f.0.clone(), f.1)) {
                            // send file to server
                            let file = File::open(&f.0).unwrap();
                            let mut reader = BufReader::new(&file);
                            let mut hasher = blake3::Hasher::new();
                            hasher.update_reader(&mut reader).unwrap();
                            let hash = hasher.finalize().to_hex().to_string();

                            if let Some(xhash) = &f.2
                                && xhash == &hash
                            {
                                return;
                            }

                            #[cfg(feature = "self_https")]
                            let mut local_headers = headers.clone();
                            #[cfg(not(feature = "self_https"))]
                            let local_headers = headers.clone();

                            #[cfg(feature = "self_https")]
                            let mut local_https_nonce = https_nonce.clone();

                            #[cfg(feature = "self_https")]
                            let mut stream_nonce_bytes = [0u8; 7];
                            #[cfg(feature = "self_https")]
                            stream_nonce_bytes.copy_from_slice(&hash.as_bytes()[0..7]);
                            #[cfg(feature = "self_https")]
                            let stream_nonce = aead::generic_array::GenericArray::<
                                u8,
                                aead::consts::U7,
                            >::from_slice(
                                &stream_nonce_bytes
                            );

                            #[cfg(feature = "self_https")]
                            new_nonce(
                                &mut local_headers,
                                &mut local_https_nonce,
                                &password,
                                &https_key,
                            );

                            #[cfg(feature = "self_https")]
                            local_headers.insert(
                                "X-Nonce-Stream",
                                HeaderValue::from_str(&BASE64_STANDARD.encode(stream_nonce_bytes))
                                    .unwrap(),
                            );

                            let file_to_send = File::open(&f.0).unwrap();

                            #[cfg(feature = "self_https")]
                            let reader = EncryptingReader::new(
                                file_to_send,
                                https_key.clone(),
                                *stream_nonce,
                            );

                            #[cfg(not(feature = "self_https"))]
                            let reader = file_to_send;

                            if let Err(_oh_no) = client
                                .post(format!("{server}/upload/{username}"))
                                .headers(local_headers)
                                .header("X-Path", &f.0)
                                .header("X-Hash", &hash)
                                .header("Content-Type", "application/octet-stream")
                                .body(Body::new(reader))
                                .send()
                            {
                                #[cfg(feature = "log")]
                                eprintln!("An error occured: {_oh_no:?}");
                            } else {
                                #[cfg(feature = "log")]
                                println!("Uploaded {}", f.0);
                            }
                        } else if diff_res.allow_deletion {
                            del_temp.lock().unwrap().push(f.0);
                        }
                    });
                });

                del.append(&mut del_temp.into_inner().unwrap());
            }
            _ => {}
        }

        if waitlist.len() > 0 && paths.len() == 0 && retries < MAX_PATH_NOT_AVAILABLE_RETRIES {
            retries += 1;
            std::thread::sleep(PATH_NOT_AVAILABLE_DELAY);
            paths = waitlist;
            waitlist = Vec::with_capacity(paths.len());
        }
    }

    if del.len() > 0 {
        let delete_req_raw = DeleteReq { files: del };

        #[cfg(feature = "self_https")]
        new_nonce(&mut headers, &mut https_nonce, &password, &https_key);

        #[cfg(feature = "self_https")]
        let delete_req = BASE64_STANDARD.encode(
            encrypt_https(
                &serde_json::to_string(&delete_req_raw).unwrap(),
                &https_key,
                &https_nonce,
            )
            .unwrap(),
        );
        #[cfg(not(feature = "self_https"))]
        let delete_req = serde_json::to_vec(&delete_req_raw).unwrap();

        let _delete_res = client
            .post(format!("{server}/delete/{username}"))
            .headers(headers.clone())
            .body(delete_req)
            .send()
            .unwrap();
    }
}

#[derive(Serialize)]
struct DiffReq {
    root: String,
    files: Vec<(String, u64)>,
}
#[derive(Deserialize, Debug)]
struct DiffRes {
    allow_deletion: bool,
    files: Vec<(String, u64, Option<String>)>,
}

#[derive(Serialize)]
struct DeleteReq {
    files: Vec<String>,
}

fn walk_dir(files: &mut Vec<(String, u64)>, path: PathBuf) {
    let paths = read_dir(&path).unwrap();

    if let Ok(exi) = exists(path.join(".noyoink"))
        && exi
    {
        // ignore folders containing a .noyoink
        return;
    }

    for path in paths {
        if let Ok(path) = path {
            if let Ok(ftype) = path.file_type() {
                let fpath = path.path();

                if ftype.is_file() {
                    let meta = path.metadata();
                    let size = if let Ok(s) = meta {
                        s.len()
                    } else {
                        UNKNOWN_FILE_SIZE
                    };

                    files.push((fpath.to_string_lossy().to_string(), size));
                } else if ftype.is_dir() {
                    walk_dir(files, fpath);
                }
            }
        }
    }
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

#[cfg(feature = "self_https")]
fn new_nonce(
    headers: &mut HeaderMap,
    https_nonce: &mut aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U12>,
    password: &String,
    https_key: &aes_gcm::Aes256Gcm,
) {
    let mut bytes = [0u8; 12];
    rand::rng().fill(&mut bytes);

    *https_nonce = aes_gcm::Nonce::from(bytes);

    headers.insert(
        "X-Nonce",
        HeaderValue::from_str(&BASE64_STANDARD.encode(https_nonce.to_vec())).unwrap(),
    );

    headers.insert(
        "X-Auth",
        HeaderValue::from_str(
            &BASE64_STANDARD.encode(encrypt_https(&password, &https_key, &https_nonce).unwrap()),
        )
        .unwrap(),
    );
}

//

#[cfg(feature = "self_https")]
struct EncryptingReader<R: Read> {
    reader: R,
    encryptor: Option<EncryptorBE32<Aes256Gcm>>,
    pending: Option<Vec<u8>>,
    buffer: Vec<u8>,
    buffer_pos: usize,
}

#[cfg(feature = "self_https")]
impl<R: Read> EncryptingReader<R> {
    fn new(
        reader: R,
        cipher: aes_gcm::Aes256Gcm,
        nonce: aes_gcm::Nonce<aes_gcm::aes::cipher::typenum::U7>,
    ) -> Self {
        Self {
            reader,
            encryptor: Some(EncryptorBE32::from_aead(cipher, &nonce)),
            pending: None,
            buffer: Vec::new(),
            buffer_pos: 0,
        }
    }
}

#[cfg(feature = "self_https")]
impl<R: Read> Read for EncryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer_pos < self.buffer.len() {
            let to_copy = (self.buffer.len() - self.buffer_pos).min(buf.len());
            buf[..to_copy]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;
            return Ok(to_copy);
        }

        let Some(ref mut encryptor) = self.encryptor else {
            return Ok(0);
        };

        if self.pending.is_none() {
            let mut chunk = vec![0u8; 65536];
            let n = self.reader.read(&mut chunk)?;
            self.pending = Some(chunk[..n].to_vec());
        }

        let mut next_chunk = vec![0u8; 65536];
        let next_n = self.reader.read(&mut next_chunk)?;

        let current = self.pending.take().unwrap();

        let encrypted = if next_n == 0 {
            let enc = self.encryptor.take().unwrap();
            enc.encrypt_last(current.as_slice())
        } else {
            self.pending = Some(next_chunk[..next_n].to_vec());
            encryptor.encrypt_next(current.as_slice())
        }
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "encrypt failed"))?;

        self.buffer = encrypted;
        self.buffer_pos = 0;

        let to_copy = self.buffer.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
        self.buffer_pos = to_copy;

        Ok(to_copy)
    }
}
