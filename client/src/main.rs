use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

const SERVER: &str = "http://localhost:1984";
const PASSWORD: &str = "hello im a password";

const PATH: &str = "./test";
const UNKNOWN_FILE_SIZE: u64 = 1_000_000_000;

fn main() {
    let username = whoami::username().unwrap_or_else(|_| "unknown".to_string());
    let mut files: Vec<(String, u64)> = Vec::with_capacity(1_000);
    walk_dir(&mut files, PathBuf::from(PATH));

    let diff_req = DiffReq {
        root: PATH.to_string(),
        files: files.clone(),
    };

    let diff_res = ureq::post(format!("{SERVER}/diff/{username}"))
        .header("X-Auth", PASSWORD)
        .send_json(diff_req)
        .unwrap()
        .body_mut()
        .read_json::<DiffRes>()
        .unwrap();

    for f in diff_res.files {
        // f.0 file path, f.1 file hash
        if files.contains(&(f.0.clone(), f.1)) {
            // send file to server
            println!("Sending: {f:?}");

            let file = File::open(&f.0).unwrap();

            let mut reader = BufReader::new(&file);
            let mut hasher = blake3::Hasher::new();
            hasher.update_reader(&mut reader).unwrap();
            let hash = hasher.finalize();

            let response = ureq::post(format!("{SERVER}/upload/{username}"))
                .header("X-Auth", PASSWORD)
                .header("X-Path", &f.0)
                .header("X-Hash", &hash.to_hex().to_string())
                .header("Content-Type", "application/octet-stream")
                .send(&file)
                .unwrap();
            println!("Response: {response:?}");
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

                    files.push((fpath.to_string_lossy().to_string(), size));
                } else if ftype.is_dir() {
                    walk_dir(files, fpath);
                }
            }
        }
    }
}
