//! Each supported export, read from a small sample file.

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use zp_import::{Format, ImportError, read, totp_address};

fn sample(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/samples")
            .join(name),
    )
    .unwrap()
}

#[test]
fn chrome_and_edge() {
    let imported = read(&sample("chrome.csv")).unwrap();
    assert_eq!(imported.format, Format::ChromeCsv);
    assert_eq!(imported.logins.len(), 2);
    let bank = &imported.logins[0];
    assert_eq!(
        (bank.title.as_str(), bank.username.as_str()),
        ("Example Bank", "alice")
    );
    assert_eq!(bank.password, r#"pa,ss "word""#);
    assert_eq!(bank.urls, ["https://bank.example.com/login"]);
    assert_eq!(bank.notes, "my note");
    // A row without a name gets its host as title.
    assert_eq!(imported.logins[1].title, "mail.example.org");
    // A row with neither user name nor password is skipped.
    assert_eq!(imported.skipped, 1);
}

#[test]
fn firefox() {
    let imported = read(&sample("firefox.csv")).unwrap();
    assert_eq!(imported.format, Format::FirefoxCsv);
    let login = &imported.logins[0];
    assert_eq!(
        (
            login.title.as_str(),
            login.username.as_str(),
            login.password.as_str()
        ),
        ("example.com", "carol", "carol-pass")
    );
}

#[test]
fn bitwarden_json_and_csv() {
    for (file, format) in [
        ("bitwarden.json", Format::BitwardenJson),
        ("bitwarden.csv", Format::BitwardenCsv),
    ] {
        let imported = read(&sample(file)).unwrap();
        assert_eq!(imported.format, format);
        let bank = imported
            .logins
            .iter()
            .find(|login| login.title == "Bank")
            .unwrap();
        assert_eq!(
            bank.urls,
            ["https://bank.example.com", "https://m.bank.example.com"],
            "{file}"
        );
        assert_eq!(bank.notes, "branch 12");
        assert_eq!(
            bank.totp.as_deref(),
            Some("otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP&issuer=Bank")
        );
        assert_eq!(imported.notes.len(), 1);
        assert_eq!(imported.notes[0].body, "purple monkey");
        // The card is not kept.
        assert_eq!(imported.skipped, 1, "{file}");
    }
    let json = read(&sample("bitwarden.json")).unwrap();
    let mail = json
        .logins
        .iter()
        .find(|login| login.title == "Mail")
        .unwrap();
    assert!(
        mail.totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/Mail:bob")
    );
    assert!(mail.urls.is_empty());
}

#[test]
fn one_password() {
    let imported = read(&sample("1password.csv")).unwrap();
    assert_eq!(imported.format, Format::OnePasswordCsv);
    let shop = &imported.logins[0];
    assert_eq!(
        (
            shop.title.as_str(),
            shop.password.as_str(),
            shop.notes.as_str()
        ),
        ("Shop", "shop-pass", "remember the coupon")
    );
    assert_eq!(shop.urls, ["https://shop.example.com"]);
    assert!(
        shop.totp
            .as_deref()
            .unwrap()
            .starts_with("otpauth://totp/Shop:dave")
    );
}

#[test]
fn what_cannot_be_read_says_why() {
    assert!(matches!(
        read(b"a,b,c\n1,2,3\n"),
        Err(ImportError::UnknownFormat)
    ));
    assert!(matches!(
        read(br#"{"encrypted": true, "items": []}"#),
        Err(ImportError::EncryptedBitwarden)
    ));
    assert!(matches!(
        read(&[0xff, 0xfe, 0x00]),
        Err(ImportError::NotText)
    ));
    assert!(matches!(read(b"{ not json"), Err(ImportError::Json(_))));
}

#[test]
fn setup_keys_become_otpauth_addresses() {
    assert_eq!(
        totp_address("jbsw y3dp ehpk 3pxp", "My Bank", "a@b.c").as_deref(),
        Some("otpauth://totp/My%20Bank:a@b.c?secret=JBSWY3DPEHPK3PXP&issuer=My%20Bank")
    );
    assert_eq!(totp_address("steam://ABCDE", "Steam", "x"), None);
    assert_eq!(totp_address("not base32 1890", "x", "y"), None);
    assert_eq!(totp_address("", "x", "y"), None);
}
