//! Fails the build with an actionable message when the SPA has not been built.
//!
//! `rust-embed` is a proc macro: pointing it at a missing directory does not
//! error, it simply embeds nothing, and the first symptom is
//! `E0599: no function or associated item named 'get' found for struct
//! 'WebAssets'` from deep inside `static_assets.rs`. That message names neither
//! the frontend nor the command to run, so a clean clone hits a dead end.
//!
//! Checking here turns it into one sentence that says exactly what to do. The
//! directory is also declared so that building the frontend re-runs this script
//! and drops the previously cached "missing" verdict.

use std::path::{Component, Path, PathBuf};

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let build = normalize(&Path::new(&manifest).join("../../web/build"));
    println!("cargo::rerun-if-changed={}", build.display());

    if build.join("index.html").is_file() {
        return;
    }

    panic!(
        "the SvelteKit frontend has not been built, so there is nothing to embed.\n\
         \n\
         Run one of:\n\
         \n\
             sh tools/build-all.sh          (frontend, then the release binary)\n\
             cd web && npm ci --include=dev && npm run build\n\
         \n\
         Expected output at: {}\n\
         `web/build` is gitignored because it is a build artifact; `cargo build`\n\
         needs it present before compiling this crate.",
        build.display()
    );
}
