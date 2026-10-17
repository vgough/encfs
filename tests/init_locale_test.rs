//! Kept apart from other tests: it sets environment variables, which is
//! only sound while no other thread reads them.

/// `init_locale` takes the locale from `LC_ALL`, then `LC_MESSAGES`, then
/// `LANG`, skipping empty values, and leaves it alone when none is set.
#[test]
fn test_init_locale_posix_precedence() {
    let cases: [(&[(&str, &str)], &str); 4] = [
        (
            &[
                ("LC_ALL", "fr_FR.UTF-8"),
                ("LC_MESSAGES", "de_DE.UTF-8"),
                ("LANG", "en_US.UTF-8"),
            ],
            "fr-FR",
        ),
        (
            &[
                ("LC_ALL", ""),
                ("LC_MESSAGES", "de_DE.UTF-8"),
                ("LANG", "fr_FR.UTF-8"),
            ],
            "de-DE",
        ),
        (&[("LANG", "fr_FR.UTF-8")], "fr-FR"),
        (&[], "en"),
    ];

    for (vars, expected) in cases {
        // SAFETY: this is the only test in its binary, so nothing else reads
        // the environment meanwhile.
        unsafe {
            for name in ["LC_ALL", "LC_MESSAGES", "LANG"] {
                std::env::remove_var(name);
            }
            for (name, value) in vars {
                std::env::set_var(name, value);
            }
        }
        rust_i18n::set_locale("en");
        encfs::init_locale();
        assert_eq!(&*rust_i18n::locale(), expected, "with {vars:?}");
    }
}
