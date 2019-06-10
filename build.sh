#!/usr/bin/env sh
BASE_DIR=$(pwd)

cd "$BASE_DIR/zcash-client-backend-wasm"
wasm-pack build
cd "$BASE_DIR/zcash-client-sdk-js"
npm install
cd "$BASE_DIR/demo-www"
npm install
