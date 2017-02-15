#!/bin/bash

extension=""

if [[ "$OS" = "Windows_NT" ]]; then
	extension=".exe"
fi

set -e
set -x

triple=$(rustup show | head -n1 | cut -d ' ' -f3)
version=$(grep 'const VERSION' src/main.rs | cut -d '"' -f 2)

mkdir -p package

cargo build

keybase sign -d -i target/debug/cmdipass$extension -o target/debug/cmdipass$extension.sig.saltpack
keybase pgp sign -d -i target/debug/cmdipass$extension -o target/debug/cmdipass$extension.sig.pgp

if [ "$OS" == "Windows_NT" ]; then
	pushd target/debug
	7z a -mx=1 ../../package/cmdipass-$version-$triple.zip cmdipass.exe*
	popd
else
	zip -j -1 package/cmdipass-$version-$triple.zip target/debug/cmdipass*
fi

