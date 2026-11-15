use encfs::config::EncfsConfig;
use typed_fuse::{PathFilesystem, SetAttr};

mod common;
use common::node;
use common::volume::{Volume, req, v7};

fn volume(modern: bool, external: bool, holes: bool, physical_size: u64) -> Volume {
    let mut config = if modern {
        v7(|_| {})
    } else {
        EncfsConfig::test_default()
    };
    config.external_iv_chaining = external;
    config.allow_holes = holes;
    let mut vol = Volume::new(config);
    // Match the on-disk representation of a C++ touch, before mounting.
    std::fs::write(vol.backing("/empty"), vec![0x42; physical_size as usize]).unwrap();
    vol.remount();
    vol
}

#[test]
fn growing_empty_files_initializes_a_header() {
    for modern in [false, true] {
        for external in [false, true] {
            for holes in [false, true] {
                for open_flags in [None, Some(libc::O_RDONLY), Some(libc::O_RDWR)] {
                    let mut vol = volume(modern, external, holes, 0);
                    let file = node(&vol.fs, &vol.root_state, "/empty", &req());
                    let opened =
                        open_flags.map(|flags| vol.fs.open(file.as_node(), flags, &req()).unwrap());
                    let size = vol.config.block_size as u64 * 2 + 37;
                    let attr = vol
                        .fs
                        .setattr(
                            file.as_node(),
                            opened.as_ref().map(|opened| &opened.handle),
                            &SetAttr {
                                size: Some(size),
                                ..Default::default()
                            },
                            &req(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "extend: modern={modern}, external={external}, holes={holes}, \
                             open_flags={open_flags:?}: {error:?}"
                            )
                        });
                    assert_eq!(attr.size, size);
                    // A pre-existing reader must see the new shared IV too.
                    if let Some(opened) = &opened {
                        let data = vol
                            .fs
                            .read(file.as_node(), &opened.handle, 0, size as usize + 1, &req())
                            .unwrap();
                        assert_eq!(data.as_ref(), vec![0; size as usize]);
                    }
                    assert_eq!(vol.read_file("/empty"), vec![0; size as usize]);
                    let writer = vol.fs.open(file.as_node(), libc::O_RDWR, &req()).unwrap();
                    vol.fs
                        .write(file.as_node(), &writer.handle, b"payload", 19, &req())
                        .unwrap();
                    vol.fs
                        .release(file.as_node(), writer.handle, &req())
                        .unwrap();
                    if let Some(opened) = opened {
                        vol.fs
                            .release(file.as_node(), opened.handle, &req())
                            .unwrap();
                    }
                    vol.remount();
                    let mut expected = vec![0; size as usize];
                    expected[19..26].copy_from_slice(b"payload");
                    assert_eq!(vol.read_file("/empty"), expected);
                }
            }
        }
    }
}

#[test]
fn zero_length_truncate_preserves_absent_header() {
    for modern in [false, true] {
        let vol = volume(modern, false, false, 0);
        let file = node(&vol.fs, &vol.root_state, "/empty", &req());
        vol.fs
            .setattr(
                file.as_node(),
                None,
                &SetAttr {
                    size: Some(0),
                    ..Default::default()
                },
                &req(),
            )
            .unwrap();
        assert_eq!(std::fs::metadata(vol.backing("/empty")).unwrap().len(), 0);
    }
}

#[test]
fn extending_partial_headers_fails_without_modifying_them() {
    for modern in [false, true] {
        let vol = volume(modern, false, false, 3);
        let before = std::fs::read(vol.backing("/empty")).unwrap();
        let file = node(&vol.fs, &vol.root_state, "/empty", &req());
        assert_eq!(
            vol.fs
                .setattr(
                    file.as_node(),
                    None,
                    &SetAttr {
                        size: Some(99),
                        ..Default::default()
                    },
                    &req()
                )
                .unwrap_err()
                .raw(),
            libc::EIO
        );
        assert_eq!(std::fs::read(vol.backing("/empty")).unwrap(), before);
    }
}
