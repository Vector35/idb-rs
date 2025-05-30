#!/bin/sh

set -e

find ../idbs/ -name '*.i64' | while read line
do
 file=$(echo $line | cut -d '/' -f 3-)
 mkdir -p "idb-rs/$(dirname ${file})"
 cargo run --all-features --manifest-path ${HOME}/src/idb-rs/Cargo.toml --release --bin idb-tools -- --input ${line} produce-idc > "idb-rs/${file%.i64}.idc"
done
