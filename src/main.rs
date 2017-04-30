extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[macro_use]
extern crate log;
extern crate env_logger;

use std::{process, env};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::fs::{self, File};
use std::error::Error;

mod keepasshttp;

const VERSION: &'static str = "0.1.1";
const USAGE: &'static str = "
cmdipass

Usage:
  cmdipass get <search-string>
  cmdipass get-one <search-string> (--index=<index> | --uuid=<uuid>) [--password-only | --username-only]
  cmdipass --version
  cmdipass (-h | --help)

Options:
  -h --help         Show this screen.
  --version         Show version.
  --index=<index>   Select the entry at this 0-indexed location.
  --uuid=<uuid>     Select the entry with this uuid.
  --password-only   Print only the password.
  --username-only   Print only the username.
";

#[derive(Debug, RustcDecodable)]
struct Args {
    cmd_get: bool,
    cmd_get_one: bool,
    flag_version: bool,
    flag_help: bool,
    arg_search_string: String,
    flag_index: Option<usize>,
    flag_uuid: Option<String>,
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

#[cfg(any(unix))]
fn write_config_file(config: &keepasshttp::Config) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new().write(true).create(true).mode(0o600).open(config_path()).unwrap();
    file.write_all(serde_json::to_string(&config).unwrap().as_bytes()).unwrap();
}

#[cfg(any(not(unix)))]
fn write_config_file(config: &keepasshttp::Config) {
    let mut file = fs::OpenOptions::new().write(true).create(true).open(config_path()).unwrap();
    file.write_all(serde_json::to_string(&config).unwrap().as_bytes()).unwrap();
}

fn show_all(entries: &Vec<keepasshttp::Entry>) {
    for(i, entry) in entries.iter().enumerate() {
        println!("{}: {}", i, entry);
    }
}

fn show_one(entries: &Vec<keepasshttp::Entry>, args: &Args) {
    let entry = if args.flag_uuid.is_some() {
        entry_by_uuid(entries, &args.flag_uuid.clone().unwrap())
    } else if args.flag_index.is_some() {
        entry_by_index(entries, &args.flag_index.clone().unwrap())
    } else {
        None
    }.unwrap_or_else(|| {
        process::exit(1);
    });

    if args.flag_password_only {
        println!("{}", entry.password);
    } else if args.flag_username_only {
        println!("{}", entry.login);
    } else {
        println!("{}", entry);
    }

}

fn entry_by_index<'a>(entries: &'a Vec<keepasshttp::Entry>, index: &usize) -> Option<&'a keepasshttp::Entry> {
    let entry = entries.get(*index);

    if entry.is_none() {
        writeln!(io::stderr(), "Could not find an entry at index {}", index).unwrap();
    }

    entry
}

fn entry_by_uuid<'a, T: AsRef<str>>(entries: &'a Vec<keepasshttp::Entry>, uuid: T) -> Option<&'a keepasshttp::Entry> {
    let entry = entries.iter().find(|e| e.uuid == uuid.as_ref());

    if entry.is_none() {
        writeln!(io::stderr(), "Could not find an entry with UUID {}", uuid.as_ref()).unwrap();
    }

    entry
}

fn get_entries<T: AsRef<str>>(search_string: T) -> Vec<keepasshttp::Entry> {
    let config = load_config().unwrap();
    let success = keepasshttp::test_associate(&config);
    if !success {
        writeln!(io::stderr(), "Config rejected by keepasshttp. Make sure that the correct database is open, or delete your config file ({}) and re-associate", config_path().to_string_lossy()).unwrap();
        process::exit(1);
    }

    keepasshttp::get_logins(&config, &search_string).unwrap_or_else(|e| {
        writeln!(io::stderr(), "Error - Server said: '{}'", e).unwrap();
        process::exit(1);
    })
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    env_logger::init().unwrap();

    if args.flag_help {
        println!("{}", USAGE);
        process::exit(0);
    }

    if args.flag_version {
        println!("cmdipass-{}", VERSION);
        process::exit(0);
    }

    if !config_exists() {
        writeln!(io::stderr(), "Config file not found at '{}', generating new key and registering with server", config_path().to_string_lossy()).unwrap();
        write_config_file(&keepasshttp::associate().unwrap());
        writeln!(io::stderr(), "Config file written.").unwrap();
    }

    let entries = get_entries(&args.arg_search_string);

    if args.cmd_get {
        show_all(&entries);
    } else if args.cmd_get_one {
        show_one(&entries, &args);
    }
}
