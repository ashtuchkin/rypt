use failure::Error;

fn main() -> Result<(), Error> {
    // NOTE: We deviate from the recommended practice of generating rust files in OUT_DIR and just
    // put them in src/proto so that we can get the autocompletion from the IDE. Let's see where it
    // gets us.
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["src/proto/header.proto"], &["src/proto/"])?;

    Ok(())
}
