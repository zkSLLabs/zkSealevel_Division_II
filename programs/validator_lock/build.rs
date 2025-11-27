use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let pid = env::var("PROGRAM_ID_VALIDATOR_LOCK")
        .ok()
        .or_else(|| env::var("PROGRAM_ID").ok());
    let code = match pid {
        Some(p) => {
            format!(
                r#"
// Auto-generated at build time. Do not edit.
#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
pub mod program_id {{
    anchor_lang::prelude::declare_id!("{pid}");
}}
pub use program_id::*;
"#,
                pid = p
            )
        }
        None => {
            // Fail fast: require env-provided program ID for deterministic builds
            panic!("PROGRAM_ID_VALIDATOR_LOCK (or PROGRAM_ID) env var is required at build time to set declare_id!");
        }
    };
    let target = out_dir.join("program_id.rs");
    fs::write(&target, code).expect("failed to write generated program_id.rs");
    println!("cargo:rerun-if-env-changed=PROGRAM_ID_VALIDATOR_LOCK");
    println!("cargo:rerun-if-env-changed=PROGRAM_ID");
}
