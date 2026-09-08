use cmake::Config;
use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    // trace-mcp vendors both trees: `libipt` is the 2.1.2 release, and
    // `libipt-master` is a pinned libipt master snapshot (2.3.0, commit
    // 306fba0a) that adds `pt_blk_resync`. Neither needs network access.
    let libipt_source = if cfg!(feature = "libipt_master") {
        Path::new("libipt-master").to_path_buf()
    } else {
        Path::new("libipt").to_path_buf()
    };
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", libipt_source.display());

    check_submodule(&libipt_source);

    let dst = Config::new(&libipt_source)
        .define("BUILD_SHARED_LIBS", "OFF")
        // temporary fix for https://github.com/intel/libipt/issues/114
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .build();

    #[cfg(windows)]
    println!("cargo:rustc-link-lib=static=libipt");
    #[cfg(not(windows))]
    println!("cargo:rustc-link-lib=static=ipt");

    // RHEL-family cmake installs static libraries under lib64.
    for lib in ["lib", "lib64"] {
        println!(
            "cargo:rustc-link-search=native={}",
            dst.join(lib).to_string_lossy()
        );
    }

    let bindings = bindgen::Builder::default()
        .header(dst.join("include").join("intel-pt.h").to_string_lossy())
        .allowlist_function("pt_.*")
        .allowlist_type("pt_.*")
        .allowlist_var("pt_.*")
        .derive_debug(true)
        .impl_debug(true)
        .derive_eq(true)
        .derive_hash(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate libipt bindings");

    bindings
        .write_to_file(Path::new(&out_dir).join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn check_submodule<P: AsRef<Path>>(path: P) {
    let path = path.as_ref();
    if !path.exists()
        || !path
            .read_dir()
            .is_ok_and(|mut content| content.next().is_some())
    {
        let error = format!("{} directory not found or empty", path.display());
        println!("cargo:warning={error}");
        println!(
            "cargo:warning=Hint: Please get the submodules with `git submodule update --init --recursive`"
        );
        panic!("{error}");
    }
}
