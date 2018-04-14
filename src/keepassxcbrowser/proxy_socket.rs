// Copyright (C) 2017-2018 Sami Vänttinen <sami.vanttinen@protonmail.com>
// Copyright (C) 2017-2018 Andy Brandt <andy@brandt.tech>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Fetched from https://github.com/varjolintu/keepassxc-proxy-rust/blob/759507e444f2ae2b6eaf12e1ee03721e2744ec6c/src/proxy_socket.rs on 2018-04-13

use std::env;
use std::io::{self, Read, Write};

#[cfg(not(windows))]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
use named_pipe::PipeClient;

pub struct ProxySocket<T> {
	inner: T,
}

impl<R: Read> Read for ProxySocket<R> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		self.inner.read(buf)
	}
}

impl<W: Write> Write for ProxySocket<W> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.inner.write(buf)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.inner.flush()
	}
}

#[cfg(windows)]
pub fn connect() -> io::Result<ProxySocket<PipeClient>> {
	let username = env::var("USERNAME").unwrap();
	let pipe_name = format!("\\\\.\\pipe\\keepassxc\\{}\\kpxc_server", username);
	let client = PipeClient::connect(pipe_name)?;
	Ok(ProxySocket { inner: client })
}

#[cfg(not(windows))]
pub fn connect() -> io::Result<ProxySocket<UnixStream>> {
	let socket_name = "kpxc_server";
	let socket: String;
	if let Ok(xdg) = env::var("XDG_RUNTIME_DIR") {
		socket = format!("{}/{}", xdg, socket_name);
	} else {
		socket = format!("/tmp/{}", socket_name);
	}
	let s = UnixStream::connect(socket)?;
	Ok(ProxySocket { inner: s })
}
