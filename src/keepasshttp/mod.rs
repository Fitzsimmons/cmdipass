mod kphcrypto;

extern crate rand;
use self::rand::{ Rng, OsRng };

extern crate base64;

extern crate serde_json;

extern crate hyper;
use self::hyper::Client;
use self::hyper::header::{Headers, ContentType, Accept};

use std::io::{self, Read, Write};
use std::io::prelude::*;

#[derive(Serialize, Debug)]
struct TestAssociateRequest {
    #[serde(rename = "Nonce")]
    nonce: String,

    #[serde(rename = "Verifier")]
    verifier: String,

    #[serde(rename = "RequestType")]
    request_type: String,

    // #[serde(rename = "TriggerUnlock")]
    // trigger_unlock: bool,

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

pub fn test_associate(config: &Config) -> bool {
    let req = TestAssociateRequest::new(config);
    let body = serde_json::to_string(&req).unwrap();
    // println!("{}", body); // TODO debug output

    let client = Client::new();
    let mut res = client.post("http://localhost:19455").
        header(ContentType::json()).
        header(Accept::json()).
        body(body.as_str()).
        send().
        unwrap();

    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();

    // println!("{}", buf); // TODO debug output
    let test_associate_response: TestAssociateResponse = serde_json::from_str(buf.as_str()).unwrap();
    test_associate_response.success
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

pub fn associate() -> Result<Config, String> {
    let associate_request = AssociateRequest::new();
    let body = serde_json::to_string(&associate_request).unwrap();
    // println!("{}", body); // TODO: figure out how to do debug output properly
    let client = Client::new();
    let mut res = client.post("http://localhost:19455").
        header(ContentType::json()).
        header(Accept::json()).
        body(body.as_str()).
        send().
        unwrap();

    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();

    let associate_response: AssociateResponse = serde_json::from_str(buf.as_str()).unwrap();

    match associate_response.success {
        true => Ok(Config { key: associate_request.key.to_owned(), id: associate_response.id.unwrap().to_owned() }),
        false => Err(String::from("Association request did not succeed. User canceled, or protocol error."))
    }
}

#[derive(Serialize, Debug)]
struct GetLoginsRequest {
    #[serde(rename = "RequestType")]
    request_type: String,

    #[serde(rename = "SortSelection")]
    sort_selection: String,

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
            sort_selection: String::from("true"),
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
    error: Option<String>
}

#[derive(Deserialize, Debug, Clone)]
pub struct RawEntry {
    #[serde(rename = "Login")]
    pub login: String,

    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "Password")]
    pub password: String,
}

pub fn get_logins<T: AsRef<str>>(config: &Config, url: T) -> Result<Vec<RawEntry>, String> {
    let get_logins_request = GetLoginsRequest::new(config, url);
    let body = serde_json::to_string(&get_logins_request).unwrap();
    // println!("{}", body); // TODO: figure out how to do debug output properly
    let client = Client::new();
    let mut res = client.post("http://localhost:19455").
        header(ContentType::json()).
        header(Accept::json()).
        body(body.as_str()).
        send().
        unwrap();

    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();

    let get_logins_response: GetLoginsResponse = serde_json::from_str(buf.as_str()).unwrap();

    match get_logins_response.success {
        true => Ok(get_logins_response.entries.clone()),
        false => Err(format!("Couldn't get logins. Server said: '{}'", get_logins_response.error.unwrap()))
    }
}

#[derive(Debug)]
pub struct Entry {
    pub login: String,
    pub name: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub key: String,
    pub id: String,
}
