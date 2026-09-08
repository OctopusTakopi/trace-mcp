# libipt-sys [![crates.io](https://img.shields.io/crates/v/libipt-sys.svg)](https://crates.io/crates/libipt-sys)

This crate contains bindgen-generated bindings for [Intel's libipt](https://github.com/intel/libipt) library.

## Building

1. Clone this repo and the submodule

    ```sh
    git clone --recursive https://github.com/sum-catnip/libipt-sys.git
    ```

2. Run `cargo build` and you should be fine. If that doesn't work, make sure you got all the requirements covered.

## Requirements

- a rust toolchain
- a C compiler that can be found by cmake
- cmake 3.5+
