#!/bin/sh

set -e

sh -c "find ../idbs/ -name '*.i64'; find ../idbs/ -name '*.idb'" | while read line
do
 file=$(echo $line | cut -d '/' -f 3-)
 mkdir -p "idb-rs/$(dirname ${file})"
 cargo run --all-features --manifest-path ${HOME}/src/idb-rs/Cargo.toml --release --bin idb-tools -- --input ${line} produce-idc "$@" > "idb-rs/${file}.idc"
done
