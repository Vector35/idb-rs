#!/bin/sh

set -e

find ../tils/ -name '*.til' | while read line
do
 file=$(echo $line | cut -d '/' -f 3-)
 mkdir -p "idb-rs-layout/$(dirname ${file})"
 cargo run --manifest-path ${HOME}/src/idb-rs/Cargo.toml --release --bin idb-tools -- --input ${line} print-tilib true > "idb-rs-layout/${file}"
done
