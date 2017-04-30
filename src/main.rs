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

macro_rules! critical_error {
    ($fmt:expr) => {{
        use std::io::{self, Write};
        use std::process;
        writeln!(io::stderr(), $fmt).unwrap();
        process::exit(1);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        use std::io::{self, Write};
        use std::process;
        writeln!(io::stderr(), $fmt, $($arg)*).unwrap();
        process::exit(1);
    }};
}

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

#[cfg(any(unix))]
fn ensure_owner_readable_only(f: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = f.metadata()?;
    let mode = metadata.permissions().mode();

    if 0o077 & mode != 0 {
        Err(io::Error::new(io::ErrorKind::Other,
            format!("Permissions {:04o} on '{path}' are too open.\n\
                It is recommended that your cmdipass config file is not accessible to others.\n\
                Try using `chmod 0600 '{path}'` to solve this problem.", mode, path = config_path().to_string_lossy())))
    } else {
        Ok(())
    }
}

#[cfg(any(not(unix)))]
fn ensure_owner_readable_only(_: &File) -> io::Result<()> {
    // TODO: Find out how to implement this on windows, if possible
    Ok(())
}

fn load_config() -> io::Result<keepasshttp::Config> {
    let mut res = File::open(config_path())?;
    ensure_owner_readable_only(&res)?;
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
        unreachable!(); // docopt's command line validation should prevent the program from ever getting here
    }.unwrap_or_else(|e| critical_error!("{}", e));

    if args.flag_password_only {
        println!("{}", entry.password);
    } else if args.flag_username_only {
        println!("{}", entry.login);
    } else {
        println!("{}", entry);
    }

}

fn entry_by_index<'a>(entries: &'a Vec<keepasshttp::Entry>, index: &usize) -> io::Result<&'a keepasshttp::Entry> {
    let entry = entries.get(*index);
    entry.ok_or(io::Error::new(io::ErrorKind::NotFound, format!("No entry found at index {}", index)))
}

fn entry_by_uuid<'a, T: AsRef<str>>(entries: &'a Vec<keepasshttp::Entry>, uuid: T) -> io::Result<&'a keepasshttp::Entry> {
    let entry = entries.iter().find(|e| e.uuid == uuid.as_ref());
    entry.ok_or(io::Error::new(io::ErrorKind::NotFound, format!("No entry found with UUID {}", uuid.as_ref())))
}

fn get_entries<T: AsRef<str>>(search_string: T) -> Vec<keepasshttp::Entry> {
    let config = load_config().unwrap_or_else(|e| critical_error!("Could not load config:\n{}", e));
    let success = keepasshttp::test_associate(&config);
    if !success {
        critical_error!("Config rejected by keepasshttp. Make sure that the correct database is open, or delete your config file ({}) and re-associate", config_path().to_string_lossy());
    }

    keepasshttp::get_logins(&config, &search_string).unwrap_or_else(|e|
        critical_error!("Error - Server said: '{}'", e)
    )
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
