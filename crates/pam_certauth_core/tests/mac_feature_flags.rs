//! Verifies cargo features wire up as expected.

#[cfg(feature = "astra-mac")]
#[test]
fn astra_mac_feature_enabled() {
    // compile-only marker: ensures feature builds.
}

#[cfg(feature = "mac-tests")]
#[test]
fn mac_tests_feature_enabled() {}

#[test]
#[allow(clippy::panic)]
fn default_build_excludes_astra_mac() {
    #[cfg(feature = "astra-mac")]
    panic!("astra-mac must NOT be in default feature set");
}
