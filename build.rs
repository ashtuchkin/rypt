use failure::Fallible;

fn main() -> Fallible<()> {
    // Compile protobufs.
    prost_build::compile_protos(&["src/proto/header.proto"], &["src/proto/"]).unwrap();

    Ok(())
}
