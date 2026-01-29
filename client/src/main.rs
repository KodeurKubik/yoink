use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};

const SERVER: &str = "http://localhost:1984";
const PASSWORD: &str = "hello im a password";

const PATH: &str = "./test";
const UNKNOWN_FILE_SIZE: u64 = 1_000_000_000;

fn main() {
    let username = whoami::username().unwrap_or_else(|_| "unknown".to_string());
    let mut files: HashMap<String, u64> = HashMap::new();
    walk_dir(&mut files, PathBuf::from(PATH));

    let diff_req = DiffReq {
        root: PATH.to_string(),
        username: username,
        password: PASSWORD.to_string(),
        files: files.clone(),
    };

    let diff_res = ureq::post(format!("{SERVER}/diff"))
        .send_json(diff_req)
        .unwrap()
        .body_mut()
        .read_json::<DiffRes>()
        .unwrap();

    for f in diff_res.files {
        // f.0 file path, f.1 file hash
        if files.contains_key(&f.0) {
            // send file to server
            println!("Should send: {}", f.0);
        }
    }
}

#[derive(Serialize)]
struct DiffReq {
    root: String,
    username: String,
    password: String,
    files: HashMap<String, u64>,
}
#[derive(Deserialize)]
struct DiffRes {
    files: HashMap<String, String>,
}

fn walk_dir(files: &mut HashMap<String, u64>, path: PathBuf) {
    let paths = fs::read_dir(path).unwrap();

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

                    files.insert(fpath.to_string_lossy().to_string(), size);
                } else if ftype.is_dir() {
                    walk_dir(files, fpath);
                }
            }
        }
    }
}
