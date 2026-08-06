EncFS is a program which provides an encrypted virtual filesystem for Linux
using the FUSE kernel module.  FUSE provides a loadable kernel module
which exports a filesystem interface to user-mode.  EncFS runs entirely in
user-mode and acts as a transparent encrypted filesystem.

Usage
-----

 - To see command line options, run the programs without an argument (or `-h`):

     encfs -h

 - To create a new encrypted filesystem:
   
     encfs [source dir] [destination mount point]

   eg.: `encfs ~/.crypt ~/crypt`.  Both directories should already exist,
   although Encfs will ask if it can create them if they do not.  If the
   `~/.crypt` directory does not already contain encrypted filesystem data,
   then the user is prompted for a password for the new encryption directory.
   The encrypted files will be stored in `~/.crypt`, and plaintext access will be
   through `~/crypt`

 - To mount an existing filesystem:

     encfs [source dir] [destination mount point]

   This works just like creating a new filesystem.  If the Encfs control file
   is found in the directory, then an attempt is made to mount an existing
   filesystem.  If the control file is not found, then the filesystem is
   created.


Technology
----------

 - Encfs uses RustCrypto-based implementations for legacy-compatible data and
   filename encryption, plus dedicated crates for V7 AEAD and Argon2 key
   derivation.

 - A user supplied password is used to decrypt a volume key, and the volume key
   is used for encrypting all file names and contents.  This makes it possible
   to change the password without needing to re-encrypt all files.

 - Key derivation: New V7 filesystems use Argon2id as the key derivation function
   (KDF), which is memory-hard and resistant to GPU/ASIC attacks. Default
   parameters are 64 MiB memory cost, 3 iterations, and 4 parallel threads.
   Legacy filesystems use PBKDF2-HMAC-SHA1 with a configurable iteration count.

 - EncFS has two encryption modes, which are used in different places:
    - Stream encryption:
	Used for filenames and partial blocks at the end of files.
	The cipher is run in CFB stream mode in multiple passes over the data,
	with data order reversal between passes to make data more
	interdependent.
    - Block encryption:
	Fixed size filesystem blocks are encrypted. Two block modes exist:

	Legacy mode (V4-V6): CBC mode with an optional per-block MAC (up to
	8 bytes). The block size is configurable and can be up to 4096 bytes.

	V7 default: AES-GCM-SIV (authenticated encryption). Each block has a
	16-byte authentication tag, providing both confidentiality and integrity.
	The SIV construction is misuse-resistant and prevents nonce-reuse issues.
	Block size defaults to 4080 bytes (4096 minus tag). This mode is the
	default for newly created V7 filesystems.

	Each block has a deterministic initialization vector derived from the
	file IV and block number, allowing simple random access within a file.

 - Filename encryption:

   Filenames are encrypted using either a stream mode or a block mode, in both
   cases with an initialization vector based on the HMAC checksum of the
   filename.
 
   Using a deterministic initial vector allows fast directory lookups, as no
   salt value needs to be looked up when converting from plaintext name to
   encrypted name.  It also means very similar filenames (such as "foo1" and
   "foo2") will encrypt to very different values, to frustrate any attempt to
   see how closely related two files are based on their encrypted names.

 - Data blocks are handled in fixed size blocks (64 byte blocks for Encfs
   versions 0.2 - 0.6, and user specified sizes in newer versions of Encfs).
   Legacy configs default to 512 bytes; V7 configs default to 4080 bytes
   (4096 minus the 16-byte AES-GCM-SIV tag).  The block size is set during
   creation of the filesystem and is constant thereafter.
   Full filesystem blocks are encrypted in the cipher's block mode as described
   above.  Partial filesystem blocks are encrypted using the cipher's stream
   mode, which involves multiple passes over the data along with data
   reordering to make the data in the partial block highly interdependent.
    
   For both modes this means that a change to a byte in the encrypted stream
   may affecting several bytes in the deciphered stream.  This makes it hard
   for any change at all to go unnoticed. 

   In legacy mode, an additional option is to store Message Authentication
   Codes with each filesystem block (up to 8 bytes overhead). In V7 AES-GCM-SIV
   mode, per-block authentication (16-byte tag) is always enabled.

   Also during filesystem creation, one can enable per-file initialization
   vectors (`uniqueIV`).  This causes a header with a random initialization
   vector to be maintained with each file.  Each file then has its own file
   IV which is combined with the block number - so that each block within a
   file has a unique initialization vector.  This makes it infeasible to copy a
   whole block from one file to another.

   For V7/AES-GCM-SIV filesystems the header (and file IV) can be either
   width:
     - Narrow (8-byte header, 64-bit file IV): the pre-existing format, still
       used by every V4-V6 filesystem, headerless (`uniqueIV=0`) configs, and
       V7 filesystems created with `encfsctl new --legacy-file-iv`.
     - Wide (12-byte header, 96-bit file IV): the default for newly created
       V7/AES-GCM-SIV filesystems. AES-GCM-SIV's nonce is always 96 bits
       either way; widening the file IV widens how many of those bits are
       unpredictable per file, reducing cross-file nonce collisions. See
       `docs/adr/0001-96-bit-file-iv-for-aes-gcm-siv.md` for the exact
       nonce/AAD byte layout of both widths.
     - Headerless (`uniqueIV=0`, 0-byte header, always 64-bit): the file IV is
       derived from the path instead of a stored header. Reverse mode
       (`encfsr`) always uses this form.

Backward Compatibility
----------------------

   At the top level of the raw (encrypted) storage for an EncFS filesystem is a
   configuration file, created automatically by EncFS when a new filesystem is
   made.

   In Encfs versions 0.2 to 0.6, the file was called ".encfs3" - meaning
   version 3 of the Encfs configuration file format (earlier versions 1 and 2
   were prior to the encfs public release).  EncFS 1.0.x used ".encfs4", and
   Encfs 1.1.x uses ".encfs5".  EncFS 1.9.x adds ".encfs6.xml" (XML)
   and v2.x adds ".encfs7" / ".encfs7.pb" (protobuf).  The encfsctl program can
   be used to show information about a filesystem.
  
   Encfs 1.1 can read and write to existing filesystems, but older versions
   will not be able to mount a filesystem created by a newer version, as the
   newer versions use algorithms and/or new options which were not previously
   available.

   V7 configuration format (new default for created filesystems):
   ---------------------------------------------------------------
   The V7 format (.encfs7) is protobuf-based and tamper-resistant. The volume
   key is encrypted with AES-256-GCM (AEAD), using the SHA-256 hash of the rest
   of the config as additional authenticated data (AAD). Any modification to
   the config (cipher params, KDF params, feature flags, etc.) invalidates the
   AAD, causing decryption to fail. The config hash is also stored and checked
   on load; a hash mismatch indicates tampering or corruption. New V7 filesystems
   default to Argon2id KDF, AES-GCM-SIV block mode, AES-256, and a 96-bit
   per-file IV (`wide_file_iv`).

   V7 also carries an authenticated `minimum_reader_version`. A build only
   opens a config whose minimum reader version it supports; a config
   requiring a newer version fails with a dedicated error rather than being
   misread. New 96-bit-file-IV volumes are intentionally **not** readable by
   tooling built before this feature: an old build cannot know the new
   protobuf fields, so it recomputes a different config hash and fails
   closed (reported as "config hash mismatch"). Use
   `encfsctl new --legacy-file-iv` (or `--no-unique-iv`, which is always
   64-bit) to create a filesystem that old tooling can still read.

Utility
-------

   In addition to the `encfs` main program, a utility `encfsctl` has been
   provided which can perform some operations on encfs filesystems.  Encfsctl
   can display information about the filesystem for the curious (the encryption
   algorithm used, key length, block size), and more importantly it can also
   change the user-supplied password used to encrypt the volume key.

Dependencies
------------

  The Rust port uses RustCrypto crates for legacy-compatible cryptographic
  operations, AES-GCM for V7 AEAD key wrapping, AES-GCM-SIV (aes-gcm-siv
  crate) for V7 block encryption, and Argon2 (argon2 crate) for key
  derivation in V7 configs.

