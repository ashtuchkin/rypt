fn main() {
    prost_build::compile_protos(&["src/header.proto"], &["src/"]).unwrap();
}
