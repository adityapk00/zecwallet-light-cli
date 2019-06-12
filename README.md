# Zcon1 WASM demo

## Dependencies

- [Rust](https://www.rust-lang.org/tools/install)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [npm](https://www.npmjs.com/get-npm)

## Building

```sh
$ ./build.sh
```

## Running the backend

Web browsers currently cannot talk directly to gRPC servers, so it is necessary to run a
proxy as part of the backend. The `envoy/` subdirectory contains a Dockerfile and config
file for an Envoy proxy that listens on `localhost:8081` and will route requests to a
`lightwalletd` frontend listening on `localhost:9067`.

See [the `lightwalletd` documentation](https://github.com/zcash-hackworks/lightwalletd)
for details on how to set up a local `lightwalletd` testnet instance. Note that when
starting the frontend, you may need to use `--bind-addr 0.0.0.0:9067` so that the Docker
container can access it.

To build and run the Envoy proxy:

```sh
$ docker build -t lightwalletd/envoy -f envoy/envoy.Dockerfile envoy
$ docker run -d -p 8081:8081 --network=host lightwalletd/envoy
```

## Running the demo

```sh
$ ln -s "$HOME/.zcash-params" demo-www/params
$ cd demo-www
$ npm run start
```

Then open http://localhost:8080/ in your browser.
