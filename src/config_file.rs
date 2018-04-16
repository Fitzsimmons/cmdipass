use std::fs::{self, File};
use std::io::{Write, Read};
use std::error::Error;
use std::path::PathBuf;
use std::env;

use error::CmdipassError;

extern crate serde;
extern crate serde_json;

pub fn config_path() -> PathBuf {
    env::var("CMDIPASS_CONFIG").map(|e| PathBuf::from(e)).unwrap_or_else(|_| {
        let mut pathbuf = env::home_dir().unwrap_or(PathBuf::from(""));
        pathbuf.push(".cmdipass");
        pathbuf
    })
}

pub fn config_exists() -> bool {
    false
    // config_path().as_path().exists()
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

pub fn load_config<Config: serde::de::DeserializeOwned>() -> Result<Config, Box<Error>> {
    let mut res = File::open(config_path())?;
    ensure_owner_readable_only(&res)?;
    let mut buf = String::new();
    res.read_to_string(&mut buf)?;

    let config: Config = serde_json::from_str(buf.as_str())?;

    // test_associate(&config)?;

    Ok(config)
}

#[cfg(any(unix))]
pub fn write_config_file<Config: serde::Serialize>(config: &Config) -> Result<(), Box<Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new().write(true).create(true).mode(0o600).open(config_path())?;
    file.write_all(serde_json::to_string(&config)?.as_bytes())?;
    Ok(())
}

#[cfg(any(not(unix)))]
pub fn write_config_file<Config: serde::Serialize>(config: &Config) -> Result<(), Box<Error>> {
    let mut file = fs::OpenOptions::new().write(true).create(true).open(config_path())?;
    file.write_all(serde_json::to_string(&config)?.as_bytes())?;
    Ok(())
}
