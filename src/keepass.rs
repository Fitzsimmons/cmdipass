use std::error::Error;

#[derive(Debug, Deserialize)]
pub struct Entry {
    pub login: String,
    pub name: String,
    pub password: String,
    pub uuid: String,
}

pub trait KeePassBackend {
    fn get_entries(&self, search_string: &str) -> Result<Vec<Entry>, Box<Error>>;
}
