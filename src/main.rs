extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

extern crate hyper;
use hyper::Client;
use hyper::header::{Headers, ContentType, Accept};
use hyper::mime::{Mime, TopLevel, SubLevel};

extern crate base64;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use std::{process, env};
use std::io::{self, Read, Write};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::error::Error;

extern crate rand;
use rand::{ Rng, OsRng };

extern crate crypto;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

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
    key: String,

    #[serde(rename = "Nonce")]
    nonce: String,

    #[serde(rename = "Verifier")]
    verifier: String,
}

impl AssociateRequest {
    fn new() -> AssociateRequest {
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
            verifier: base64::encode(encrypt(nonce_b64.as_bytes(), &key, &nonce).unwrap().as_slice()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AssociateResponse {
    #[serde(rename = "Success")]
    success: bool,

    #[serde(rename = "Id")]
    id: Option<String>,
}

// Copied verbatim from the rust-crypto sample code, which coincidentally is exactly what we need
// https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs
fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn test_associate() -> String {
    let mut key: [u8; 32] = [0; 32];
    let mut nonce: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);

    let verifier = encrypt(&nonce, &key, &nonce).unwrap();

    let req = TestAssociateRequest {
        nonce: base64::encode(&nonce),
        verifier: base64::encode(&verifier),
        request_type: String::from("test-associate"),
        trigger_unlock: false,
        id: String::from("PHP"),
    };

    serde_json::to_string(&req).unwrap()
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

fn write_config_file(request: &AssociateRequest, response: &AssociateResponse) {
    let config = Config {
        key: request.key.to_owned(),
        id: response.id.to_owned().unwrap(),
    };
    let mut file = File::create(config_path()).unwrap();
    file.write_all(serde_json::to_string(&config).unwrap().as_bytes()).unwrap();
}

fn associate() {
    println!("Config file not found at '{}', generating new key and registering with server", config_path().to_string_lossy());

    let associate_request = AssociateRequest::new();
    let body = serde_json::to_string(&associate_request).unwrap();
    println!("{}", body);
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
