use failure::Error;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Error> {
    // NOTE: We deviate from the recommended practice of generating rust files in OUT_DIR and just
    // put them in src/proto so that we can get the autocompletion from the IDE. Let's see where it
    // gets us.
    let proto_files = &[Path::new("src/proto/header.proto")];
    let include_dirs = &[Path::new("src/proto/")];
    let output_dir = "src/proto";
    let output_file = Path::new(output_dir).join("rypt.rs");

    fn mtime(path: &Path) -> SystemTime {
        path.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(UNIX_EPOCH)
    }

    let output_file_mtime = mtime(&output_file);

    if proto_files
        .iter()
        .any(|path| mtime(path) >= output_file_mtime)
    {
        prost_build::Config::new()
            .out_dir(output_dir)
            .compile_protos(proto_files, include_dirs)?;
    }

    Ok(())
}
