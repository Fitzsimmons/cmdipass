extern crate toml;

use std::env;
use std::fs::File;
use std::convert::AsRef;
use std::io::{Write, Read, BufWriter};
use std::path::Path;

fn main() {
    let mut f = File::open("Cargo.toml").unwrap();
    let mut raw = String::new();

    f.read_to_string(&mut raw).unwrap();
    let cargo = raw.parse::<toml::Value>().unwrap();

    let path = env::var_os("OUT_DIR").unwrap();
    let path : &Path = path.as_ref();
    let path = path.join("cargo-version.rs");

    let mut output = BufWriter::new(File::create(&path).unwrap());
    write!(output, "const VERSION: &'static str = {};\n", cargo["package"]["version"]).unwrap();
}
