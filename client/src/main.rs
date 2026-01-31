// dont open any window on windows
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, read_dir},
    io::BufReader,
    path::PathBuf,
};

const YOINK_CONFIG_FILE: &str = include_str!(".yoinkconfig");
const UNKNOWN_FILE_SIZE: u64 = 1_000_000_000;

fn main() {
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
    let path = yoink_config.get("PATH").unwrap().to_string();
    let username = yoink_config
        .get("USERNAME")
        .unwrap_or(&"unknown".to_string())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>();

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

    for f in diff_res.files {
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
                continue;
            }

            let file_to_send = File::open(&f.0).unwrap();
            let _response = ureq::post(format!("{server}/upload/{username}"))
                .header("User-Agent", "YoinkSync/0.1")
                .header("X-Auth", &password)
                .header("X-Path", &f.0)
                .header("X-Hash", &hash)
                .header("Content-Type", "application/octet-stream")
                .send(file_to_send);
        }
    }
}

#[derive(Serialize)]
struct DiffReq {
    root: String,
    files: Vec<(String, u64)>,
}
#[derive(Deserialize)]
struct DiffRes {
    files: Vec<(String, u64, Option<String>)>,
}

fn walk_dir(files: &mut Vec<(String, u64)>, path: PathBuf) {
    let paths = read_dir(path).unwrap();

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
