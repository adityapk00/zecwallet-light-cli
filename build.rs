fn main() {
    // Build proto files
    tower_grpc_build::Config::new()
        .enable_server(false)
        .enable_client(true)
        .build(
            &["proto/service.proto", "proto/compact_formats.proto"],
            &["proto"],
        )
        .unwrap_or_else(|e| panic!("protobuf compilation failed: {}", e));
    println!("cargo:rerun-if-changed=proto/service.proto");
}
