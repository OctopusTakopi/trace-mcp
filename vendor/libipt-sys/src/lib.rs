#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_offset_with_cast)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(not(feature = "libipt_master"))]
    fn libipt_version() {
        let libipt_version = unsafe { pt_library_version() };
        assert_eq!(
            (
                libipt_version.major,
                libipt_version.minor,
                libipt_version.patch
            ),
            (2, 1, 2)
        );
    }
}
