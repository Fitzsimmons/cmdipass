extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate hyper;
use hyper::Client;
use hyper::header::{Headers, ContentType, Accept};

extern crate rand;
use rand::{ Rng, OsRng };

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use std::{process, env};
use std::io::{self, Read, Write};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::error::Error;

mod keepasshttp;

const VERSION: &'static str = "0.1.0";
const USAGE: &'static str = "
cmdipass

Usage:
  cmdipass get <search-string> [<index>] [--password-only | --username-only]
  cmdipass --version
  cmdipass (-h | --help)
";

#[derive(Debug, RustcDecodable)]
struct Args {
    cmd_get: bool,
    flag_version: bool,
    flag_help: bool,
    arg_search_string: Option<String>,
    arg_index: Option<String>,
    flag_password_only: bool,
    flag_username_only: bool
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    key: String,
    id: String,
}

fn config_path() -> PathBuf {
    env::var("CMDIPASS_CONFIG").map(|e| PathBuf::from(e)).unwrap_or_else(|_| {
        let mut pathbuf = env::home_dir().unwrap_or(PathBuf::from(""));
        pathbuf.push(".cmdipass");
        pathbuf
    })
}

fn config_exists() -> bool {
    config_path().as_path().exists()
}

fn load_config() -> io::Result<Config> {
    let mut res = File::open(config_path())?;
    let mut buf = String::new();
    res.read_to_string(&mut buf)?;

    let config: Config = serde_json::from_str(buf.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e.description())))?;
    Ok(config)
}

fn write_config_file(request: &keepasshttp::AssociateRequest, response: &keepasshttp::AssociateResponse) {
    let config = Config {
        key: request.key.to_owned(),
        id: response.id.to_owned().unwrap(),
    };
    let mut file = File::create(config_path()).unwrap();
    file.write_all(serde_json::to_string(&config).unwrap().as_bytes()).unwrap();
}

// fn test_associate() -> String {
//     let mut key: [u8; 32] = [0; 32];
//     let mut nonce: [u8; 16] = [0; 16];
//     let mut rng = OsRng::new().ok().unwrap();
//     rng.fill_bytes(&mut key);
//     rng.fill_bytes(&mut nonce);

//     let verifier = keepasshttp::crypto::encrypt(&nonce, &key, &nonce).unwrap();

//     let req = TestAssociateRequest {
//         nonce: base64::encode(&nonce),
//         verifier: base64::encode(&verifier),
//         request_type: String::from("test-associate"),
//         trigger_unlock: false,
//         id: String::from("PHP"),
//     };

//     serde_json::to_string(&req).unwrap()
// }

fn associate() {
    writeln!(io::stderr(), "Config file not found at '{}', generating new key and registering with server", config_path().to_string_lossy()).unwrap();

    let associate_request = keepasshttp::AssociateRequest::new();
    let body = serde_json::to_string(&associate_request).unwrap();
    println!("{}", body);
    let client = Client::new();
    let mut res = client.post("http://localhost:19455").
        header(ContentType::json()).
        header(Accept::json()).
        body(body.as_str()).
        send().
        unwrap();

    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();

    let associate_response: keepasshttp::AssociateResponse = serde_json::from_str(buf.as_str()).unwrap();

    match associate_response.success {
        true => write_config_file(&associate_request, &associate_response),
        false => {
            writeln!(io::stderr(), "Association request did not succeed. User canceled, or protocol error").unwrap();
            std::process::exit(1);
        }
    }
}


fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    if args.flag_help {
        println!("{}", USAGE);
        process::exit(0);
    }

    if args.flag_version {
        println!("cmdipass-{}", VERSION);
        process::exit(0);
    }

    let client = Client::new();
    let mut res = client.get("http://localhost").send().unwrap();
    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();

    if !config_exists() {
        associate();
    }


}
