# GitHub Issues Analysis

This document categorizes GitHub issues from the original C++ EncFS repository based on their relevance to the Rust port.

## C++ Implementation Specific
These issues are likely specific to the C++ codebase, build system (CMake), or dependencies (Boost, OpenSSL C++ API), and may not directly apply to the Rust implementation unless similar logic errors were made.

<!-- *   **#660: cmake failing under Cygwin?** - Build system specific. -->
*   **[#656](https://github.com/vgough/encfs/issues/656): segmentation fault on Version 5 directories with SSL 3.0** - C++ crash/memory safety.
*   **[#652](https://github.com/vgough/encfs/issues/652): MacOS: fails to compile** - C++ build error.
*   **[#651](https://github.com/vgough/encfs/issues/651): segmentation fault on Blowfish since ubuntu jammy** - C++ crash.
<!-- *   **#643: Don't set RUNPATH if it is the system search path** - CMake build configuration. -->
<!-- *   **#641: Does not build with Clang / libc++ 13** - C++ standard library compatibility. -->
*   **[#630](https://github.com/vgough/encfs/issues/630): Error: encfs has been disabled because it requires FUSE!** - Package/Install issue.
*   **[#629](https://github.com/vgough/encfs/issues/629): Binary installation for Mac...** - Packaging/distribution.
<!-- *   **#447: Casts should be checked** - C++ type safety/integer overflow risks (Rust handles this differently, though logic still needs care). -->

## Rust Port Relevant
These issues relate to the EncFS format, security design, FUSE behavior, or feature requests that apply to any implementation of EncFS.

### Security Design & Crypto
Issues identifying weaknesses in the EncFS protocol or format. The Rust port inherits these weakness if it strictly follows the spec, but should be aware of them for potential "2.0" improvements or warnings.

*   **[#636](https://github.com/vgough/encfs/issues/636): Replace PKCS5_PBKDF2_HMAC_SHA1 with Argon2id** - Modernize KDF.
*   **[#17](https://github.com/vgough/encfs/issues/17): Information Leakage Between Decryption and MAC Check** - Protocol flaw (MAC-then-Encrypt).
*   **[#16](https://github.com/vgough/encfs/issues/16): 64-bit Initialization Vectors** - Protocol weakness.
*   **[#13](https://github.com/vgough/encfs/issues/13): 64-bit MACs** - Protocol weakness.
*   **[#11](https://github.com/vgough/encfs/issues/11): File Holes are Not Authenticated** - Protocol weakness.
*   **[#10](https://github.com/vgough/encfs/issues/10): Generating Block IV by XORing Block Number** - Protocol weakness (IV reuse risk).
*   **[#9](https://github.com/vgough/encfs/issues/9): Stream Cipher Used to Encrypt Last File Block** - Protocol weakness.
*   **[#8](https://github.com/vgough/encfs/issues/8): Same Key Used for Encryption and Authentication** - Protocol weakness.

### Feature Requests
Functionality requested by users that could be implemented in the Rust port.

*   **[#665](https://github.com/vgough/encfs/issues/665): Sync conflits support for --reversewrite** - Better handling of sync conflicts.
*   **[#662](https://github.com/vgough/encfs/issues/662): disable creation option** - CLI flag feature.
*   **[#654](https://github.com/vgough/encfs/issues/654): Encrypted "--reverse" filenames are always different** - Deterministic encryption in reverse mode.
*   **[#618](https://github.com/vgough/encfs/issues/618): encfsctl cat support for decrypting file contents from STDIN** - CLI utility enhancement.
*   **[#599](https://github.com/vgough/encfs/issues/599): Handle supplementary groups** - FUSE permission handling.
*   **[#497](https://github.com/vgough/encfs/issues/497): storage of .encfs6.xml - ENCFS6_CONFIG** - Config file handling.
*   **[#496](https://github.com/vgough/encfs/issues/496): expert configuration mode - ask for PBKDF2 runtime** - UX improvement.
*   **[#495](https://github.com/vgough/encfs/issues/495): fuse3?** - Support for FUSE3 (Rust `fuser` crate might support this).
*   **[#273](https://github.com/vgough/encfs/issues/273): Chained IV Filename in reverse mode** - Feature parity/enhancement.
*   **[#240](https://github.com/vgough/encfs/issues/240): Support multiple writers to underlying file system** - Concurrency/Locking feature.
*   **[#225](https://github.com/vgough/encfs/issues/225): encfs max block size limit** - Allow larger blocks.
*   **[#166](https://github.com/vgough/encfs/issues/166): Request: Support for inotify in --reverse mode** - FUSE/Kernel feature integration.
*   **[#135](https://github.com/vgough/encfs/issues/135): enhance exit code** - CLI UX.
*   **[#37](https://github.com/vgough/encfs/issues/37): Feature request: ignore invalid file names in encfsctl decode** - Tooling robustness.
*   **[#7](https://github.com/vgough/encfs/issues/7): alternative filename storage for very long filenames** - Handling filenames > 255 bytes after encryption.
*   **[#5](https://github.com/vgough/encfs/issues/5): implement per-directory configuration** - Architecture change.
*   **[#4](https://github.com/vgough/encfs/issues/4): add communication channel with running filesystem** - Control interface.
*   **[#3](https://github.com/vgough/encfs/issues/3): encrypt extended attributes** - Xattr support.

### Bugs & Behavior behavior
Issues describing unexpected behavior, data corruption, or FUSE quirks. These should be tested against the Rust port.

*   **[#676](https://github.com/vgough/encfs/issues/676): --extpass return code is not checked** - Error handling logic.
*   **[#672](https://github.com/vgough/encfs/issues/672): Data corruption after backup EncFS directory** - Data integrity.
*   **[#667](https://github.com/vgough/encfs/issues/667): encfs reversewrite mode with MAXPATH files** - Edge case with long paths.
*   **[#661](https://github.com/vgough/encfs/issues/661): Can't mount existing filesystem on M1 mac** - Arch specific or crypto bug?
*   **[#646](https://github.com/vgough/encfs/issues/646): Unexpected permission resolution when used with --public** - FUSE permissions logic.
*   **[#640](https://github.com/vgough/encfs/issues/640): Truncating of file name** - Filename handling bug.
*   **[#634](https://github.com/vgough/encfs/issues/634): Dropbox getAttr error** - Interaction with cloud sync / filesystem errors.
*   **[#627](https://github.com/vgough/encfs/issues/627): "Bad Message" in files when using Dropbox** - Corrupted file handling.
*   **[#612](https://github.com/vgough/encfs/issues/612): encfs idle parameter is confusing** - Idle timeout logic.
*   **[#606](https://github.com/vgough/encfs/issues/606): ERROR Invalid data size, not multiple of block size** - Data handling/Corrupted data.
*   **[#603](https://github.com/vgough/encfs/issues/603): Setuid and setcap not working** - FUSE mount options/capabilities.
*   **[#587](https://github.com/vgough/encfs/issues/587): EncFS Performance over NFS is very poor** - Performance optimization.
*   **[#574](https://github.com/vgough/encfs/issues/574): encfsctl decode takes only 99 arguments** - CLI limitation.
*   **[#550](https://github.com/vgough/encfs/issues/550): Some files exist in the target, but are not shown by 'ls' nor 'dir'** - Readdir consistency.
*   **[#543](https://github.com/vgough/encfs/issues/543): attr_set: Operation not supported** - Xattr implementation.
*   **[#531](https://github.com/vgough/encfs/issues/531): Modification dates are lost when untarring** - Metadata preservation.
*   **[#250](https://github.com/vgough/encfs/issues/250): Drive content refresh on macOS** - Caching/FUSE invalidation.
*   **[#52](https://github.com/vgough/encfs/issues/52): Inaccurate nanoseconds in timestamp for fstat** - Time precision.

### Questions / Info
*   **[#669](https://github.com/vgough/encfs/issues/669): Silent install** - Usage question.
*   **[#668](https://github.com/vgough/encfs/issues/668): Can we decrypt a file system using older version** - Compatibility question.
*   **[#666](https://github.com/vgough/encfs/issues/666): Can I decrypt single files?** - Usage question.
*   **[#659](https://github.com/vgough/encfs/issues/659): Current security status** - Documentation.
*   **[#644](https://github.com/vgough/encfs/issues/644): is it safe that save encrypt data and .encfs6.xml in a place that other can get** - Security model question.
*   **[#642](https://github.com/vgough/encfs/issues/642): deleted files recovery** - Usage/Recovery.
*   **[#620](https://github.com/vgough/encfs/issues/620): Help with Automount** - Usage.
*   **[#615](https://github.com/vgough/encfs/issues/615): Reconstruct configuration file** - Recovery.
*   **[#607](https://github.com/vgough/encfs/issues/607): EncFS natively works on Win10!** - Platform info.
