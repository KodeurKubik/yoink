// dont open any window on windows
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
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
const MAX_PATH_NOT_AVAILABLE_RETRIES: usize = 15;
const MULTI_THREAD_COUNT: usize = 5;
const PATH_NOT_AVAILABLE_DELAY: Duration = Duration::from_secs(2);

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
                waitlist.push(path);
            }
            Ok(true) => {
                let mut files: Vec<(String, u64)> = Vec::with_capacity(1_000);
                walk_dir(&mut files, PathBuf::from(&path));

                let diff_req = DiffReq {
                    root: path,
                    files: files.clone(),
                };

                let diff_res = ureq::post(format!("{server}/diff/{username}"))
                    .header("User-Agent", "YoinkSync/0.1")
                    .header("X-Auth", &password)
                    .send_json(diff_req)
                    .unwrap()
                    .body_mut()
                    .read_json::<DiffRes>()
                    .unwrap();

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

                            let file_to_send = File::open(&f.0).unwrap();

                            if let Err(oh_no) = ureq::post(format!("{server}/upload/{username}"))
                                .header("User-Agent", "YoinkSync/0.1")
                                .header("X-Auth", &password)
                                .header("X-Path", &f.0)
                                .header("X-Hash", &hash)
                                .header("Content-Type", "application/octet-stream")
                                .send(&file_to_send)
                            {
                                eprintln!("An error occured: {oh_no:?}");
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
        let delete_req = DeleteReq { files: del };

        let _delete_res = ureq::post(format!("{server}/delete/{username}"))
            .header("User-Agent", "YoinkSync/0.1")
            .header("X-Auth", &password)
            .send_json(delete_req)
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
