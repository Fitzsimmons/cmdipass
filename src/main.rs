extern crate docopt;
use docopt::Docopt;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[macro_use]
extern crate log;
extern crate env_logger;

use std::process;
use std::io;

mod keepasshttp;
use keepasshttp::KeePassHttp;

mod keepass;
use keepass::{KeePassBackend, Entry};

macro_rules! critical_error {
    ($fmt:expr) => {{
        use std::process;
        ewriteln!($fmt).unwrap();
        process::exit(1);
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        use std::io::{self, Write};
        use std::process;
        writeln!(io::stderr(), $fmt, $($arg)*).unwrap();
        process::exit(1);
    }};
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

const USAGE: &'static str = "
cmdipass

Usage:
  cmdipass get [--xc] <search-string>
  cmdipass get-one [--xc] <search-string> (--index=<index> | --uuid=<uuid>) [--password-only | --username-only]
  cmdipass --version
  cmdipass (-h | --help)

Options:
  -h --help         Show this screen.
  --version         Show version.
  --index=<index>   Select the entry at this 0-indexed location.
  --uuid=<uuid>     Select the entry with this uuid.
  --password-only   Print only the password.
  --username-only   Print only the username.
  --xc              Use KeePassXC-Browser protocol.
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_get: bool,
    cmd_get_one: bool,
    flag_version: bool,
    flag_help: bool,
    arg_search_string: String,
    flag_index: Option<usize>,
    flag_uuid: Option<String>,
    flag_password_only: bool,
    flag_username_only: bool,
    flag_xc: bool,
}

fn show_all(entries: &Vec<Entry>) {
    for(i, entry) in entries.iter().enumerate() {
        println!("{}: {}", i, entry);
    }
}

fn show_one(entries: &Vec<Entry>, args: &Args) {
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

fn entry_by_index<'a>(entries: &'a Vec<Entry>, index: &usize) -> io::Result<&'a Entry> {
    let entry = entries.get(*index);
    entry.ok_or(io::Error::new(io::ErrorKind::NotFound, format!("No entry found at index {}", index)))
}

fn entry_by_uuid<'a, T: AsRef<str>>(entries: &'a Vec<Entry>, uuid: T) -> io::Result<&'a Entry> {
    let entry = entries.iter().find(|e| e.uuid == uuid.as_ref());
    entry.ok_or(io::Error::new(io::ErrorKind::NotFound, format!("No entry found with UUID {}", uuid.as_ref())))
}

// fn get_entries<T: AsRef<str>>(search_string: T) -> Vec<Entry> {
//     let config = load_config().unwrap_or_else(|e| critical_error!("Could not load config:\n{}", e));
//     let success = keepasshttp::test_associate(&config);
//     if !success {
//         critical_error!("Config rejected by keepasshttp. Make sure that the correct database is open, or delete your config file ({}) and re-associate", config_path().to_string_lossy());
//     }

//     keepasshttp::get_logins(&config, &search_string).unwrap_or_else(|e|
//         critical_error!("Error - Server said: '{}'", e)
//     )
// }

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.deserialize()).unwrap_or_else(|e| e.exit());

    env_logger::init().unwrap();

    if args.flag_help {
        println!("{}", USAGE);
        process::exit(0);
    }

    if args.flag_version {
        println!("cmdipass-{}", VERSION);
        process::exit(0);
    }

    let keepass_backend: Box<KeePassBackend> = match args.flag_xc {
        // true => KeePassXC::new(),
        true => unimplemented!(),
        false => Box::new(KeePassHttp::new().unwrap_or_else(|e| critical_error!("{}", e)))
    };

    let entries = keepass_backend.get_entries(&args.arg_search_string);

    if args.cmd_get {
        show_all(&entries);
    } else if args.cmd_get_one {
        show_one(&entries, &args);
    }
}
