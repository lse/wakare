#!/bin/sh

DIR=$(dirname $0)

for f in $DIR/*/;do
    gcc "$f/main.c" -no-pie -o "$f/prog.nopie"
    gcc "$f/main.c" -fPIE -o "$f/prog.pie"
    chmod +x "$f/prog.nopie"
    chmod +x "$f/prog.pie"
done
