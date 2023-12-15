extern crate bindgen;
extern crate cc;

use build_helpers::{Error, LibraryConfig};
use bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

#[derive(Debug)]
struct MacroCallback {
    macros: Arc<RwLock<HashSet<String>>>,
}

impl ParseCallbacks for MacroCallback {
    fn will_parse_macro(&self, name: &str) -> MacroParsingBehavior {
        self.macros.write().unwrap().insert(name.into());

        if name == "IPPORT_RESERVED" {
            return MacroParsingBehavior::Ignore;
        }

        MacroParsingBehavior::Default
    }
}

/// Returns output dir.
fn get_out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap())
}

/// Returns SPDK root dir.
fn get_spdk_root_dir() -> PathBuf {
    PathBuf::from(env::var("SPDK_ROOT_DIR").expect("SPDK_ROOT_DIR must be set"))
}

/// Finds and configures SPDK library.
fn spdk_lib_config() -> Result<LibraryConfig, Error> {
    let spdk_root = get_spdk_root_dir();
    println!("SPDK root directory: {spdk_root:?}");

    let mut spdk_lib = LibraryConfig::new();

    spdk_lib.add_inc(spdk_root.join("include"))?;
    spdk_lib.add_inc(spdk_root.join("include/spdk_internal"))?;
    spdk_lib.add_inc(spdk_root.join("module"))?;
    spdk_lib.add_inc(spdk_root.join("lib"))?;

    Ok(spdk_lib)
}

/// Compiles SPDK helper sources.
fn compile_spdk_helpers<P>(inc_dirs: P) -> Result<(), Error>
where
    P: IntoIterator,
    P::Item: AsRef<Path>,
{
    let files = vec![
        "helpers/logwrapper.h",
        "helpers/logwrapper.c",
        "helpers/nvme_helper.h",
        "helpers/nvme_helper.c",
        "helpers/spdk_helper.h",
        "helpers/spdk_helper.c",
    ];

    let mut src_files = Vec::new();

    for s in &files {
        match fs::canonicalize(s) {
            Ok(p) => {
                println!("cargo:rerun-if-changed={}", p.to_str().unwrap());
                if p.extension().unwrap() == "c" {
                    src_files.push(p);
                }
            }
            Err(e) => {
                return Err(Error::Generic(format!(
                    "Bad SPDK helper source {s}: {e}"
                )))
            }
        }
    }

    cc::Build::new()
        .includes(inc_dirs)
        .files(src_files)
        .compile("helpers");

    Ok(())
}

fn main() {
    #![allow(unreachable_code)]
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    panic!("Rust support crate is only for x86_64 (Nehalem or later) and aarch64 (with crypto) ISAs.");

    #[cfg(not(target_os = "linux"))]
    panic!("Rust support crate works only on linux");

    // Configure SPDK library.
    println!("\nConfiguring SPDK library...");
    let spdk_lib = match spdk_lib_config() {
        Ok(c) => {
            println!("Successfully configured SPDK library");
            c
        }
        Err(e) => {
            eprintln!("\nFailed to configure SPDK: {e}\n");
            std::process::exit(1);
        }
    };

    let inc_dirs = spdk_lib.get_inc_paths();

    // Compile SPDK helpers.
    println!("\nCompiling SPDK helpers...");
    match compile_spdk_helpers(&inc_dirs) {
        Ok(_) => {
            println!("Successfully compiled SPDK helpers");
        }
        Err(e) => {
            eprintln!("\nFailed to complie SPDK helpers: {e}\n");
            std::process::exit(1);
        }
    }

    // Generate Rust bindings for SPDK.
    let clang_args: Vec<String> = inc_dirs
        .iter()
        .map(|p| {
            let s = p.to_str().unwrap();
            println!("cargo:rerun-if-changed={s}");
            format!("-I{s}")
        })
        .collect();

    let macros = Arc::new(RwLock::new(HashSet::new()));

    let bindings = bindgen::Builder::default()
        .clang_args(clang_args)
        .header("wrapper.h")
        .formatter(bindgen::Formatter::Rustfmt)
        .allowlist_function(".*.aio.*")
        .allowlist_function(".*.crypto_disk.*")
        .allowlist_function(".*.iscsi.*")
        .allowlist_function(".*.lock_lba_range")
        .allowlist_function(".*.lvol.*")
        .allowlist_function(".*.lvs.*")
        .allowlist_function(".*.uring.*")
        .allowlist_function("^iscsi.*")
        .allowlist_function("^spdk.*")
        .allowlist_function("create_malloc_disk")
        .allowlist_function("delete_malloc_disk")
        .allowlist_function("^bdev.*")
        .allowlist_function("^nbd_.*")
        .allowlist_function("^vbdev_.*")
        .allowlist_function("^nvme_cmd_.*")
        .allowlist_function("^nvme_status_.*")
        .allowlist_function("^nvmf_subsystem_find_listener")
        .allowlist_function("^nvmf_subsystem_set_ana_state")
        .allowlist_function("^nvmf_subsystem_set_cntlid_range")
        .allowlist_function("^nvmf_tgt_accept")
        .allowlist_function("^nvme_qpair_.*")
        .allowlist_function("^nvme_ctrlr_.*")
        .allowlist_function("^nvme_transport_qpair_.*")
        .blocklist_type("^longfunc")
        .allowlist_type("^spdk_nvme_ns_flags")
        .allowlist_type("^spdk_nvme_registered_ctrlr.*")
        .allowlist_type("^spdk_nvme_reservation.*")
        .allowlist_type("spdk_nvme_status_code_type")
        .rustified_enum("spdk_nvme_status_code_type")
        .allowlist_type("spdk_nvme_generic_command_status_code")
        .rustified_enum("spdk_nvme_generic_command_status_code")
        .allowlist_type("spdk_nvme_command_specific_status_code")
        .rustified_enum("spdk_nvme_command_specific_status_code")
        .allowlist_type("spdk_nvme_media_error_status_code")
        .rustified_enum("spdk_nvme_media_error_status_code")
        .allowlist_type("spdk_nvme_path_status_code")
        .rustified_enum("spdk_nvme_path_status_code")
        .allowlist_var("^NVMF.*")
        .allowlist_var("^SPDK.*")
        .allowlist_var("^spdk.*")
        .trust_clang_mangling(false)
        .opaque_type("^spdk_nvme_sgl_descriptor")
        .opaque_type("^spdk_nvme_ctrlr_data")
        .opaque_type("^spdk_nvme_feat_async_event_configuration.*")
        .opaque_type("^spdk_nvmf_fabric_connect.*")
        .opaque_type("^spdk_nvmf_fabric_prop.*")
        .layout_tests(false)
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .prepend_enum_name(false)
        .size_t_is_usize(false)
        .generate_inline_functions(true)
        .parse_callbacks(Box::new(MacroCallback { macros }));

    #[cfg(target_arch = "x86_64")]
    let bindings = bindings.clang_arg("-march=nehalem");

    let bindings = bindings
        .generate()
        .expect("Unable to generate SPDK bindings");

    let out_path = get_out_dir();
    bindings
        .write_to_file(out_path.join("libspdk.rs"))
        .expect("Couldn't write SPDK bindings!");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
}
