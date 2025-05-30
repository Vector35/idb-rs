#!/bin/sh

find ../tils/ -name '*.til' | while read line
do
 file=$(echo $line | cut -d '/' -f 3-)
 mkdir -p "tilib/$(dirname ${file})"
 steam-run ${HOME}/opt/ida-free-pc-9.1/tools/tilib/tilib -l ${line} > "tilib/${file}"
done
