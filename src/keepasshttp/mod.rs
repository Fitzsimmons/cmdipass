mod kphcrypto;

extern crate rand;
use self::rand::{ Rng, OsRng };

use std::path::PathBuf;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::env;
use std::fmt;
use std::error::Error;
use error::CmdipassError;

use keepass::{KeePassBackend, Entry};

extern crate base64;

extern crate serde;
extern crate serde_json;

extern crate hyper;
use self::hyper::{Client, status};
use self::hyper::header::{ContentType, Accept};

#[derive(Serialize, Debug)]
struct TestAssociateRequest {
    #[serde(rename = "Nonce")]
    nonce: String,

    #[serde(rename = "Verifier")]
    verifier: String,

    #[serde(rename = "RequestType")]
    request_type: String,

    #[serde(rename = "Id")]
    id: String,
}

impl TestAssociateRequest {
    fn new(config: &Config) -> TestAssociateRequest {
        let mut nonce: [u8; 16] = [0; 16];
        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(&mut nonce);

        let nonce_b64 = base64::encode(&nonce);
        let key = base64::decode(config.key.as_ref()).unwrap();

        TestAssociateRequest {
            request_type: String::from("test-associate"),
            nonce: base64::encode(&nonce),
            verifier: base64::encode(kphcrypto::encrypt(nonce_b64.as_bytes(), &key, &nonce).unwrap().as_slice()),
            id: config.id.to_owned(),
        }
    }
}

#[derive(Deserialize, Debug)]
struct TestAssociateResponse {
    #[serde(rename = "Success")]
    success: bool,
}

pub fn test_associate(config: &Config) -> Result<(), Box<Error>> {
    let req = TestAssociateRequest::new(config);
    let test_associate_response: TestAssociateResponse = request(&req)?;

    match test_associate_response.success {
        true => Ok(()),
        false => Err(Box::new(CmdipassError::new(format!("Config rejected by keepasshttp. Make sure that the correct database is open, or delete your config file ({}) and re-associate", config_path().to_string_lossy()))))
    }
}

#[derive(Serialize, Debug)]
struct AssociateRequest {
    #[serde(rename = "RequestType")]
    request_type: String,

    #[serde(rename = "Key")]
    pub key: String,

    #[serde(rename = "Nonce")]
    nonce: String,

    #[serde(rename = "Verifier")]
    verifier: String,
}

impl AssociateRequest {
    pub fn new() -> AssociateRequest {
        let mut key: [u8; 32] = [0; 32];
        let mut nonce: [u8; 16] = [0; 16];
        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);

        let nonce_b64 = base64::encode(&nonce);

        AssociateRequest {
            request_type: String::from("associate"),
            key: base64::encode(&key),
            nonce: base64::encode(&nonce),
            verifier: base64::encode(kphcrypto::encrypt(nonce_b64.as_bytes(), &key, &nonce).unwrap().as_slice()),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct AssociateResponse {
    #[serde(rename = "Success")]
    pub success: bool,

    #[serde(rename = "Id")]
    pub id: Option<String>,
}

pub fn associate() -> Result<Config, Box<Error>> {
    let associate_request = AssociateRequest::new();
    let associate_response: AssociateResponse = request(&associate_request)?;

    match associate_response.success {
        true => Ok(Config { key: associate_request.key.to_owned(), id: associate_response.id.unwrap().to_owned() }),
        false => Err(Box::new(CmdipassError::new("Association request did not succeed. User canceled, or protocol error.")))
    }
}

#[derive(Serialize, Debug)]
struct GetLoginsRequest {
    #[serde(rename = "RequestType")]
    request_type: String,

    #[serde(rename = "Id")]
    id: String,

    #[serde(rename = "Nonce")]
    nonce: String,

    #[serde(rename = "Verifier")]
    verifier: String,

    #[serde(rename = "Url")]
    url: String,
}

impl GetLoginsRequest {
    fn new<T: AsRef<str>>(config: &Config, url: T) -> GetLoginsRequest {
        let mut nonce: [u8; 16] = [0; 16];
        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(&mut nonce);

        let nonce_b64 = base64::encode(&nonce);
        let key = base64::decode(config.key.as_ref()).unwrap();

        GetLoginsRequest {
            request_type: String::from("get-logins"),
            nonce: base64::encode(&nonce),
            verifier: base64::encode(kphcrypto::encrypt(nonce_b64.as_bytes(), &key, &nonce).unwrap().as_slice()),
            id: config.id.to_owned(),
            url: base64::encode(kphcrypto::encrypt(url.as_ref().as_bytes(), &key, &nonce).unwrap().as_slice()),
        }
    }
}

#[derive(Deserialize, Debug)]
struct GetLoginsResponse {
    #[serde(rename = "Count")]
    count: u8,

    #[serde(rename = "Entries")]
    entries: Vec<RawEntry>,

    #[serde(rename = "Success")]
    success: bool,

    #[serde(rename = "Error")]
    error: Option<String>,

    #[serde(rename = "Nonce")]
    nonce: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RawEntry {
    #[serde(rename = "Login")]
    login: String,

    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Password")]
    password: String,

    #[serde(rename = "Uuid")]
    uuid: String,
}

impl RawEntry {
    pub fn decrypt<T: AsRef<str>, U: AsRef<str>>(&self, key_b64: T, iv_b64: U) -> Entry {
        let key = base64::decode(key_b64.as_ref()).unwrap();
        let iv = base64::decode(iv_b64.as_ref()).unwrap();

        Entry {
            login: String::from_utf8_lossy(&kphcrypto::decrypt(base64::decode(&self.login).unwrap().as_slice(), &key, &iv).unwrap()).into_owned(),
            name: String::from_utf8_lossy(&kphcrypto::decrypt(base64::decode(&self.name).unwrap().as_slice(), &key, &iv).unwrap()).into_owned(),
            password: String::from_utf8_lossy(&kphcrypto::decrypt(base64::decode(&self.password).unwrap().as_slice(), &key, &iv).unwrap()).into_owned(),
            uuid: String::from_utf8_lossy(&kphcrypto::decrypt(base64::decode(&self.uuid).unwrap().as_slice(), &key, &iv).unwrap()).into_owned()
        }
    }
}

pub fn get_logins<T: AsRef<str>>(config: &Config, url: T) -> Result<Vec<Entry>, Box<Error>> {
    let get_logins_request = GetLoginsRequest::new(config, url);
    let get_logins_response: GetLoginsResponse = request(&get_logins_request)?;

    match get_logins_response.success {
        true => {
            Ok(get_logins_response.entries.iter().map(|re| re.decrypt(&config.key, &get_logins_response.nonce)).collect())
        },
        false => Err(
            Box::new(
                CmdipassError::new(format!("Couldn't get logins. Server said: '{}'", get_logins_response.error.unwrap()))
            )
        )
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name: {} || Login: {} || Password: {} || UUID: {}", self.name, self.login, self.password, self.uuid)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub key: String,
    pub id: String,
}

fn request<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(request: &Req) -> Result<Resp, Box<Error>> {
    let body = serde_json::to_string(&request).unwrap();
    debug!("{}", body);
    let client = Client::new();
    let mut res = client.post("http://localhost:19455").
        header(ContentType::json()).
        header(Accept::json()).
        body(body.as_str()).
        send().map_err(|e|
            Box::new(CmdipassError::new(
                format!("Error while trying to contact KeePassHttp: {}\nMake sure that KeePass is running and the database is unlocked.", e))
            )
        )?;

    debug!("{:?}", res);
    match res.status {
        status::StatusCode::Ok => {
            let mut buf = String::new();
            res.read_to_string(&mut buf)?;
            debug!("{}", buf);

            let response: Resp = serde_json::from_str(buf.as_str())?;
            Ok(response)
        },
        _ => Err(Box::new(CmdipassError::new(format!("Error while trying to contact KeePassHttp: {}\nMake sure that KeePass is running and the database is unlocked.", res.status))))
    }
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
fn ensure_owner_readable_only(f: &File) -> Result<(), Box<Error>> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = f.metadata()?;
    let mode = metadata.permissions().mode();

    if 0o077 & mode != 0 {
        Err(Box::new(CmdipassError::new(format!("Permissions {:04o} on '{path}' are too open.\n\
                It is recommended that your cmdipass config file is not accessible to others.\n\
                Try using `chmod 0600 '{path}'` to solve this problem.", mode, path = config_path().to_string_lossy()))))
    } else {
        Ok(())
    }
}

#[cfg(any(not(unix)))]
fn ensure_owner_readable_only(_: &File) -> Result<(), Box<Error>> {
    // TODO: Find out how to implement this on windows, if possible
    Ok(())
}

fn load_config() -> Result<Config, Box<Error>> {
    let mut res = File::open(config_path())?;
    ensure_owner_readable_only(&res)?;
    let mut buf = String::new();
    res.read_to_string(&mut buf)?;

    let config: Config = serde_json::from_str(buf.as_str())?;

    test_associate(&config)?;

    Ok(config)
}

#[cfg(any(unix))]
fn write_config_file(config: &Config) -> Result<(), Box<Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new().write(true).create(true).mode(0o600).open(config_path())?;
    file.write_all(serde_json::to_string(&config)?.as_bytes())?;
    Ok(())
}

#[cfg(any(not(unix)))]
fn write_config_file(config: &keepasshttp::Config) -> Result<(), String> {
    let mut file = fs::OpenOptions::new().write(true).create(true).open(config_path())?;
    file.write_all(serde_json::to_string(&config)?.as_bytes())?;
    Ok(())
}

pub struct KeePassHttp {
    config: Config,
}

impl KeePassBackend for KeePassHttp {
    fn get_entries(&self, search_string: &str) -> Result<Vec<Entry>, Box<Error>> {
        get_logins(&self.config, &search_string)
    }
}

impl KeePassHttp {
    pub fn new() -> Result<KeePassHttp, Box<Error>> {
        let config: Config = match config_exists() {
            true => load_config()?,
            false => {
                eprintln!("Config file not found at '{}'. Generating new key and registering with server.", config_path().to_string_lossy());
                let config = associate()?;
                write_config_file(&config)?;
                eprintln!("Config file written.");
                config
            }
        };
        Ok(KeePassHttp { config: config })
    }
}
