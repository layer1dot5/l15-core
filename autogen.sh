#!/bin/sh

srcroot=`pwd`

(cd contrib/secp256k1 && autoreconf -if --warnings=all)
(cd src/wasm && autoreconf -if --warnings=all)
(cd node && autoreconf -if --warnings=all)
autoreconf -if --warnings=all
