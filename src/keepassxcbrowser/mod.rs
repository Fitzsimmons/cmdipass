use std::error::Error;
use error::CmdipassError;

extern crate rand;

extern crate serde;
extern crate serde_json;

extern crate base64;

extern crate sodiumoxide;
use self::sodiumoxide::crypto::box_;

use keepass::{KeePassBackend, Entry};
use config_file::{config_exists, load_config, config_path, write_config_file};

mod protocol;
use self::protocol::Session;

mod proxy_socket;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    our_secret_key: box_::SecretKey,
    id: String,
    backend_type: String,
}

impl Config {
    fn new(secret_key: box_::SecretKey, id: String) -> Config {
        Config { our_secret_key: secret_key, id: id, backend_type: String::from("KeePassXC-Browser") }
    }
}

fn register() -> Result<Config, Box<Error>> {
    eprintln!("Config file not found at '{}'. Generating new key and registering with server.", config_path().to_string_lossy());
    let (_our_public_key, our_secret_key) = box_::gen_keypair();
    let session = Session::new(our_secret_key)?;
    let config = protocol::associate(&session)?;

    debug!("{:?}", config);
    write_config_file(&config)?;
    eprintln!("Config file written.");

    Ok(config)
}

pub struct KeePassXCBrowser {
    session: protocol::Session,
}

impl KeePassXCBrowser {
    pub fn new() -> Result<KeePassXCBrowser, Box<Error>> {
        sodiumoxide::init();

        let config: Config = match config_exists() {
            true => load_config()?,
            false => register()?
        };

        let session = protocol::test_associate(&config)?;
        Ok(KeePassXCBrowser { session: session })
    }
}

impl KeePassBackend for KeePassXCBrowser {
    fn get_entries(&self, search_string: &str) -> Result<Vec<Entry>, Box<Error>> {
        protocol::get_entries(&self.session, search_string)
    }
}
