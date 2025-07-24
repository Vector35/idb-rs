#!/bin/sh


set -e

find ../idbs/ -name '*.i64' | while read line
do
 file=$(echo $line | cut -d '/' -f 3-)
 echo $file
 mkdir -p "ida/$(dirname ${file})"
 ${IDA_DIR}/ida -A -S"${HOME}/src/idb-rs/resources/idc-diff/gen-ida.idc ${HOME}/src/idb-rs/resources/idc-diff/ida/${file}.idc" "${HOME}/src/idb-rs/resources/idbs/${file}"
done

find ../idbs/ -name '*.idb' | while read line
do
 file=$(echo $line | cut -d '/' -f 3-)
 echo $file
 mkdir -p "ida/$(dirname ${file})"
 cp "${HOME}/src/idb-rs/resources/ida/idbs/${file}" /tmp/tmp.idb
 ${IDA_DIR}/ida -S"${HOME}/src/idb-rs/resources/idc-diff/gen-ida.idc ${HOME}/src/idb-rs/resources/idc-diff/ida/${file}.idc" /tmp/tmp.idb
 rm -f /tmp/tmp.idb /tmp/tmp.i64
done
