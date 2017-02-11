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

#[derive(Serialize, Deserialize, Debug)]
struct TestAssociateRequest {
    #[serde(rename = "Nonce")]
    nonce: String,

    #[serde(rename = "Verifier")]
    verifier: String,

    #[serde(rename = "RequestType")]
    request_type: String,

    #[serde(rename = "TriggerUnlock")]
    trigger_unlock: bool,

    #[serde(rename = "Id")]
    id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TestAssociateResponse {
    #[serde(rename = "Success")]
    success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct AssociateResponse {
    #[serde(rename = "Success")]
    pub success: bool,

    #[serde(rename = "Id")]
    pub id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RawEntry {
    #[serde(rename = "Login")]
    login: String,

    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Password")]
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub key: String,
    pub id: String,
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
