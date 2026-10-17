use std::collections::{BTreeMap, BTreeSet};

/// The `%{...}` placeholders in `text`.
fn placeholders(text: &str) -> BTreeSet<&str> {
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find("%{") {
        let end = rest[start..]
            .find('}')
            .unwrap_or_else(|| panic!("Unclosed placeholder in: {text}"));
        found.insert(&rest[start + 2..start + end]);
        rest = &rest[start + end + 1..];
    }
    found
}

/// Every key has a translation in every locale, and each one uses the same
/// placeholders as the English text. The locales are loaded the way
/// rust-i18n loads them when it compiles them in.
#[test]
fn test_locales_completeness_and_placeholder_parity() {
    let locales_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/locales");
    let translations: BTreeMap<String, BTreeMap<String, String>> =
        rust_i18n_support::load_locales(locales_dir, |_| false);

    let expected_langs = ["en", "fr", "de"];
    for lang in expected_langs {
        assert!(translations.contains_key(lang), "No {lang} translations");
    }
    let unexpected: Vec<_> = translations
        .keys()
        .filter(|lang| !expected_langs.contains(&lang.as_str()))
        .collect();
    assert!(unexpected.is_empty(), "Unexpected locales: {unexpected:?}");

    let all_keys: BTreeSet<&String> = translations.values().flat_map(|t| t.keys()).collect();
    assert!(!all_keys.is_empty(), "No translations found in locales/");

    for key in all_keys {
        let missing: Vec<_> = expected_langs
            .iter()
            .filter(|lang| !translations[**lang].contains_key(key))
            .collect();
        assert!(
            missing.is_empty(),
            "Key '{key}' is missing translations for: {missing:?}"
        );

        let en = placeholders(&translations["en"][key]);
        for lang in ["fr", "de"] {
            let other = placeholders(&translations[lang][key]);
            assert_eq!(
                en, other,
                "Placeholder mismatch in key '{key}': en={en:?} vs {lang}={other:?}"
            );
        }
    }
}
