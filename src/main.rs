extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

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
  cmdipass get <search-string>
  cmdipass get-one <search-string> <index> [--password-only | --username-only]
  cmdipass --version
  cmdipass (-h | --help)
";

#[derive(Debug, RustcDecodable)]
struct Args {
    cmd_get: bool,
    flag_version: bool,
    flag_help: bool,
    arg_search_string: String,
    arg_index: Option<u8>,
    flag_password_only: bool,
    flag_username_only: bool
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

fn load_config() -> io::Result<keepasshttp::Config> {
    let mut res = File::open(config_path())?;
    let mut buf = String::new();
    res.read_to_string(&mut buf)?;

    let config: keepasshttp::Config = serde_json::from_str(buf.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e.description())))?;
    Ok(config)
}

fn write_config_file(config: &keepasshttp::Config) {
    let mut file = File::create(config_path()).unwrap();
    file.write_all(serde_json::to_string(&config).unwrap().as_bytes()).unwrap();
}

fn handle_entries(result: &Result<Vec<keepasshttp::Entry>, String>, args: &Args) {
    let entries = result.as_ref().unwrap_or_else(|e| {
        writeln!(io::stderr(), "Error - Server said: '{}'", e);
        process::exit(1);
    });

    match args.arg_index {
        Some(index) => {
            let entry = &entries.get(index as usize).unwrap_or_else(|| {
                writeln!(io::stderr(), "Results did not contain an entry at index {}", index);
                process::exit(1);
            });

            if args.flag_username_only {
                println!("{}", entry.login);
            } else if args.flag_password_only {
                println!("{}", entry.password);
            } else {
                println!("{}", entry);
            }
        },
        None => {
            for(i, entry) in entries.iter().enumerate() {
                println!("{}: {}", i, entry);
            }
        }
    }
}

fn get(args: &Args) {
    let config = load_config().unwrap();
    let success = keepasshttp::test_associate(&config);
    if !success {
        writeln!(io::stderr(), "Config rejected by keepasshttp. Make sure that the correct database is open, or delete your config file ({}) and re-associate", config_path().to_string_lossy()).unwrap();
        process::exit(1);
    }
    let entries = keepasshttp::get_logins(&config, &args.arg_search_string);
    handle_entries(&entries, args);
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

    match config_exists() {
        true => {
            get(&args);
        },
        false => {
            writeln!(io::stderr(), "Config file not found at '{}', generating new key and registering with server", config_path().to_string_lossy()).unwrap();
            write_config_file(&keepasshttp::associate().unwrap());
            writeln!(io::stderr(), "Config file written.").unwrap();
            get(&args);
        }
    }
}
