use std::io::{Read, Write};
use std::error::Error;

use error::CmdipassError;

extern crate serde;
extern crate serde_json;
use self::serde::{Serialize, Serializer, Deserialize, Deserializer};

extern crate rand;
use self::rand::{ Rng, OsRng };

extern crate base64;

extern crate sodiumoxide;
use self::sodiumoxide::crypto::box_;

use keepassxcbrowser::proxy_socket;
use keepassxcbrowser::Config;

use keepass;

pub struct Session {
    our_secret_key: box_::SecretKey,
    server_public_key: box_::PublicKey,
    client_id: ClientId,
}

impl Session {
    pub fn new(our_secret_key: box_::SecretKey) -> Result<Session, Box<Error>> {
        let client_id = ClientId::new();
        let our_public_key = our_secret_key.public_key();
        let server_public_key = get_server_public_key(&our_public_key, &client_id)?;
        Ok(Session { our_secret_key: our_secret_key, server_public_key: server_public_key, client_id: client_id })
    }
}

trait Request: serde::Serialize {
    fn action(&self) -> String;
}

// ==== Change Public Keys ====

fn get_server_public_key(our_public_key: &box_::PublicKey, client_id: &ClientId) -> Result<box_::PublicKey, Box<Error>> {
    let req = ChangePublicKeysRequest::new(our_public_key, client_id);
    let resp: ChangePublicKeysResponse = raw_request(&req)?;
    let server_public_key = box_::PublicKey::from_slice(base64::decode(&resp.public_key)?.as_slice()).ok_or(
        Box::new(CmdipassError::new("Could not parse server's public key: incorrect size")))?;

    Ok(server_public_key)
}

#[derive(Serialize, Debug)]
struct ChangePublicKeysRequest {
    action: String,
    #[serde(rename = "publicKey", serialize_with = "serialize_public_key")]
    public_key: box_::PublicKey,
    #[serde(serialize_with = "serialize_nonce")]
    nonce: box_::Nonce,
    #[serde(rename = "clientID")]
    client_id: ClientId,
}

impl ChangePublicKeysRequest {
    pub fn new(our_public_key: &box_::PublicKey, client_id: &ClientId) -> ChangePublicKeysRequest {
        let nonce = box_::gen_nonce();

        ChangePublicKeysRequest {
            action: String::from("change-public-keys"),
            public_key: our_public_key.clone(),
            nonce: nonce,
            client_id: client_id.clone()
        }
    }
}

#[derive(Deserialize, Debug)]
struct ChangePublicKeysResponse {
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

// ==== Associate ====

pub fn associate(session: &Session) -> Result<Config, Box<Error>> {
    let request = AssociateRequest::new(&session.our_secret_key.public_key());
    let response: AssociateResponse = encrypted_request(session, &request)?;

    Ok(Config::new(session.our_secret_key.clone(), response.id))
}

#[derive(Debug, Serialize)]
struct AssociateRequest {
    action: String,
    #[serde(serialize_with = "serialize_public_key", rename = "key")]
    our_public_key: box_::PublicKey,
}

impl AssociateRequest {
    fn new(our_public_key: &box_::PublicKey) -> AssociateRequest {
        AssociateRequest { action: String::from("associate"), our_public_key: our_public_key.clone() }
    }
}

impl Request for AssociateRequest {
    fn action(&self) -> String {
        self.action.clone()
    }
}

#[derive(Debug, Deserialize)]
struct AssociateResponse {
    id: String,
}

// ==== Test Associate ====

pub fn test_associate(config: &Config) -> Result<Session, Box<Error>> {
    let session = Session::new(config.our_secret_key.clone())?;
    let req = TestAssociateRequest::new(config);
    let _resp: TestAssociateResponse = encrypted_request(&session, &req)?;

    Ok(session)
}

#[derive(Serialize, Debug)]
struct TestAssociateRequest {
    action: String,
    id: String,
    #[serde(serialize_with = "serialize_public_key", rename = "key")]
    our_public_key: box_::PublicKey,
}

impl TestAssociateRequest {
    pub fn new(config: &Config) -> TestAssociateRequest {
        TestAssociateRequest { action: String::from("test-associate"), id: config.id.clone(), our_public_key: config.our_secret_key.public_key() }
    }
}

impl Request for TestAssociateRequest {
    fn action(&self) -> String {
        self.action.clone()
    }
}

#[derive(Deserialize, Debug)]
struct TestAssociateResponse {
    id: String,
}

// ==== Get Entries ====

pub fn get_entries(session: &Session, search_string: &str) -> Result<Vec<keepass::Entry>, Box<Error>> {
    let req = GetEntriesRequest::new(search_string);
    let resp: GetEntriesResponse = encrypted_request(session, &req)?;

    Ok(resp.entries)
}

#[derive(Deserialize, Debug)]
struct GetEntriesResponse {
    entries: Vec<keepass::Entry>
}

impl GetEntriesRequest {
    pub fn new(search_string: &str) -> GetEntriesRequest {
        GetEntriesRequest { action: String::from("get-logins"), url: String::from(search_string) }
    }
}

impl Request for GetEntriesRequest {
    fn action(&self) -> String {
        self.action.clone()
    }
}

#[derive(Serialize, Debug)]
struct GetEntriesRequest {
    action: String,
    url: String,
}

// ==== Communication ====

fn encrypted_request<Req, Resp>(session: &Session, request: &Req) -> Result<Resp, Box<Error>>
    where Req: Request, Resp: serde::de::DeserializeOwned {

    let encrypted_request = encrypt_request(session, request)?;
    let encrypted_response: EncryptedResponse = raw_request(&encrypted_request)?;

    decrypt_response(session, &encrypted_response)
}

fn encrypt_request<Req>(session: &Session, request: &Req) -> Result<EncryptedRequest, Box<Error>> where Req: Request {
    let nonce = box_::gen_nonce();
    let serialized_plaintext = serde_json::to_string(&request)?;
    debug!("Seralized plaintext: {}", serialized_plaintext);
    let encrypted_message = box_::seal(serialized_plaintext.as_bytes(), &nonce, &session.server_public_key, &session.our_secret_key);
    let escaped_ciphertext = base64::encode(&encrypted_message);

    Ok(EncryptedRequest {
        action: request.action(),
        client_id: session.client_id.clone(),
        nonce: nonce,
        message: escaped_ciphertext,
    })
}

fn decrypt_response<Resp>(session: &Session, encrypted_response: &EncryptedResponse) -> Result<Resp, Box<Error>>
    where Resp: serde::de::DeserializeOwned {

    if encrypted_response.error.is_some() {
        let failure_details = encrypted_response.error.as_ref().unwrap();
        return Err(Box::new(CmdipassError::new(format!("{} action failed: {}", encrypted_response.action, failure_details))));
    }

    let raw_ciphertext = base64::decode(encrypted_response.message.as_ref().ok_or(
        CmdipassError::new("Neither message nor error was present in the response from the server. Protocol error?")
    )?)?;

    let raw_plaintext = String::from_utf8(
        box_::open(&raw_ciphertext, &encrypted_response.nonce.unwrap(), &session.server_public_key, &session.our_secret_key)
        .map_err(|_| CmdipassError::new("Verification of server message failed. Broken protocol implementation or interception attempt has occurred."))?)?;

    debug!("Decrypted plaintext: {}", raw_plaintext);
    Ok(serde_json::from_str(&raw_plaintext)?)
}

fn raw_request<Req, Resp>(request: &Req) -> Result<Resp, Box<Error>>
    where Req: serde::Serialize, Resp: serde::de::DeserializeOwned {
    let body = serde_json::to_string(&request)?;
    debug!("Raw request body: {}", body);

    let mut socket = proxy_socket::connect()?;
    socket.write(&body.as_bytes())?;
    socket.flush()?;

    let mut buf: [u8; 1024 * 16] = [0; 1024 * 16];
    let length = socket.read(&mut buf)?;
    // TODO: Check if there is more to read on the socket?

    let decoded = String::from_utf8_lossy(&buf[0..length]);
    debug!("Raw response body: {}", decoded);
    let response: Resp = serde_json::from_str(&decoded)?;
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct EncryptedResponse {
    action: String,
    error: Option<String>,
    message: Option<String>,
    #[serde(deserialize_with = "deserialize_optional_nonce", default)]
    nonce: Option<box_::Nonce>,
}

#[derive(Debug, Serialize)]
struct EncryptedRequest {
    action: String,
    message: String,
    #[serde(serialize_with = "serialize_nonce")]
    nonce: box_::Nonce,
    #[serde(rename = "clientID")]
    client_id: ClientId,
}

#[derive(Debug, Clone)]
pub struct ClientId([u8; 24]);

impl ClientId {
    pub fn new() -> ClientId {
        let mut client_id = ClientId([0; 24]);
        let mut rng = OsRng::new().unwrap();
        rng.fill_bytes(&mut client_id.0);
        client_id
    }
}

impl Serialize for ClientId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(base64::encode(&self.0).as_str())
    }
}

fn serialize_public_key<S>(public_key: &box_::PublicKey, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
    serializer.serialize_str(base64::encode(public_key.as_ref()).as_str())
}

fn serialize_nonce<S>(nonce: &box_::Nonce, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
    serializer.serialize_str(base64::encode(nonce.as_ref()).as_str())
}

fn deserialize_optional_nonce<'de, D>(d: D) -> Result<Option<box_::Nonce>, D::Error> where D: Deserializer<'de> {
    use self::serde::de::Error;

    let option: Option<String> = Option::deserialize(d)?;
    let nonce_option = match option {
        Some(s) => {
            let raw = base64::decode(&s).map_err(|e| D::Error::custom(format!("{}", e)))?;
            Some(box_::Nonce::from_slice(&raw).ok_or(D::Error::custom("Failed to parse nonce from server: incorrect size"))?)
        },
        None => None
    };
    Ok(nonce_option)
}
