use std::io::{Seek, SeekFrom};

use libunrealpak::{read_footer, write_footer, Footer, FooterCommon, Version, MAGIC};

static AES_KEY: &str = "lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=";

const V5_FOOTER_COMMON: FooterCommon = FooterCommon {
    magic: MAGIC,
    version: Version::V5,
    index_offset: 0,
    index_size: 10,
    index_hash: [
        5, 250, 114, 174, 234, 72, 106, 152, 121, 87, 255, 41, 46, 157, 12, 8, 72, 24, 194, 18,
    ],
};

#[test]
fn test_write_footer_v5() {
    let reference_footer = Footer::V4ToV6 {
        is_encrypted: false,
        common: V5_FOOTER_COMMON,
    };
    let Footer::V4ToV6 {
            common: FooterCommon { version, .. },
            ..
        } = reference_footer else { panic!(); };

    let reference_bytes = include_bytes!("../tests/empty_packs/pack_v5.pak");
    let reference_bytes =
        &reference_bytes[(reference_bytes.len() - version.footer_size() as usize)..];

    let mut our_footer = Vec::new();
    let mut writer = std::io::Cursor::new(&mut our_footer);
    write_footer(&mut writer, &reference_footer).unwrap();

    assert_eq!(reference_bytes, &our_footer[..])
}

#[test]
fn test_identity_footer_v5() {
    let reference_footer = Footer::V4ToV6 {
        is_encrypted: false,
        common: V5_FOOTER_COMMON,
    };

    let mut buf = Vec::new();
    let mut writer = std::io::Cursor::new(&mut buf);
    write_footer(&mut writer, &reference_footer).unwrap();
    let mut reader = std::io::Cursor::new(&mut buf);
    let our_footer = read_footer(&mut reader, Version::V5).unwrap();

    assert_eq!(our_footer, reference_footer);
}

#[test]
fn test_read_footer_v5() {
    let reference_footer = Footer::V4ToV6 {
        is_encrypted: false,
        common: V5_FOOTER_COMMON,
    };
    let Footer::V4ToV6 {
            common: FooterCommon { version, .. },
            ..
        } = reference_footer else { panic!(); };

    let bytes = include_bytes!("./empty_packs/pack_v5.pak");
    let mut reader = std::io::Cursor::new(bytes);
    reader
        .seek(SeekFrom::End(-(version.footer_size() as i64)))
        .unwrap();
    let our_footer = read_footer(&mut reader, Version::V5).unwrap();

    assert_eq!(reference_footer, our_footer);
}
