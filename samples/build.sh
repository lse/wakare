#!/bin/sh

DIR=$(dirname $0)

for f in $DIR/*/;do
    gcc "$f/main.c" -no-pie -o "$f/prog"
    chmod +x "$f/prog"
done
