#!/bin/bash

extension=""

if [[ "$OS" = "Windows_NT" ]]; then
	extension=".exe"
fi

set -exo pipefail

triple=$(rustup show | head -n1 | cut -d ' ' -f3 || true) # crashes in windows for some reason, but still gives output

mkdir -p package

cargo build

version=$(cargo run -- --version | sed s/cmdipass-//)

keybase sign -d -i target/debug/cmdipass$extension -o target/debug/cmdipass$extension.sig.saltpack
keybase pgp sign -d -i target/debug/cmdipass$extension -o target/debug/cmdipass$extension.sig.pgp

if [ "$OS" == "Windows_NT" ]; then
	pushd target/debug
	7z a -mx=1 ../../package/cmdipass-$version-$triple.zip cmdipass.exe*
	popd
else
	zip -j -1 package/cmdipass-$version-$triple.zip target/debug/cmdipass*
fi

