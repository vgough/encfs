#!/bin/bash
# Builds EncFS volumes with the C++ implementation, for the backward
# compatibility check in docs/testing/cpp-compatibility.md.
#
# Runs on any Linux machine with C++ `encfs` and FUSE (`apt install encfs`).
# Writes $OUT/<variant>/cipher (the ciphertext tree, config inside) and
# $OUT/<variant>/manifest (what the C++ mount showed), plus
# $OUT/encfs-version. The password of every volume is "test".
#
# Manifest lines: `<sha1> f ./path` for regular files, `- l ./path -> target`
# for symlinks.
set -u
OUT=${OUT:-$HOME/cppvols}
PW=test

rm -rf "$OUT"
mkdir -p "$OUT"
encfs --version > "$OUT/encfs-version" 2>&1
uname -srm >> "$OUT/encfs-version"
grep PRETTY_NAME /etc/os-release >> "$OUT/encfs-version" 2>/dev/null

unmount() {
  fusermount3 -u "$1" 2>/dev/null || fusermount -u "$1"
}

# setfield <config> <element> <value>: edits a V6 XML config. The volume key
# isn't bound to these fields, so a volume made in standard mode can be
# turned into another variant before any file is written.
setfield() {
  sed -i "s|<$2>[^<]*</$2>|<$2>$3</$2>|" "$1"
}

# The files every volume gets, written through the C++ mount.
populate() {
  cd "$1" || return 1
  printf 'hello\n' > small
  : > empty                       # no header: C++ writes it with the first data
  touch empty2
  head -c 5000 /dev/urandom > multi       # partial last block
  head -c 1024 /dev/urandom > oneblock
  head -c 2048 /dev/urandom > twoblocks
  head -c 300000 /dev/urandom > big
  mkdir -p sub/dir
  head -c 3000 /dev/urandom > sub/dir/nested   # chained name IVs
  printf 'x' > 'spaced name ü.txt'
  dd if=/dev/urandom of=sparse bs=100 count=1 status=none
  dd if=/dev/urandom of=sparse bs=100 count=1 seek=100 conv=notrunc status=none
  truncate -s 50000 extended; printf 'tail' >> extended
  head -c 5000 /dev/urandom > shrunk; truncate -s 1500 shrunk
  head -c 700 /dev/urandom > appended; head -c 900 /dev/urandom >> appended
  ln -s sub/dir/nested link
  ln -s /etc/hostname abslink
  ln -s ../../small sub/dir/up
  cd /
}

manifest() {
  (cd "$1" && find . -type f -print0 | sort -z | while IFS= read -r -d '' f; do
     echo "$(sha1sum < "$f" | cut -d' ' -f1) f $f"; done
   cd "$1" && find . -type l -print0 | sort -z | while IFS= read -r -d '' f; do
     echo "- l $f -> $(readlink "$f")"; done)
}

# make_vol <name> <standard|paranoia|expert> [element=value ...]
# Expert mode reads its answers from $EXPERT_ANSWERS.
make_vol() {
  local name=$1 mode=$2; shift 2
  local c=$OUT/$name/cipher p=/tmp/encfs-compat-mnt-$name log=$OUT/$name.log
  mkdir -p "$c" "$p"
  if [ "$mode" = expert ]; then
    printf '%s' "$EXPERT_ANSWERS" | encfs --extpass="echo $PW" "$c" "$p" >"$log" 2>&1
  else
    echo "$PW" | encfs "--$mode" -S "$c" "$p" >"$log" 2>&1
  fi
  if ! mountpoint -q "$p"; then
    echo "$name: SKIPPED, C++ failed to create it (see $log)"
    rm -rf "$OUT/$name"
    return
  fi
  unmount "$p"
  for kv in "$@"; do setfield "$c/.encfs6.xml" "${kv%%=*}" "${kv#*=}"; done
  if ! echo "$PW" | encfs -S "$c" "$p" >>"$log" 2>&1; then
    echo "$name: SKIPPED, C++ refuses to mount it (see $log)"
    rm -rf "$OUT/$name"
    return
  fi
  populate "$p"
  manifest "$p" > "$OUT/$name/manifest"
  unmount "$p"
  # C++ must read back what it wrote, or the manifest proves nothing.
  echo "$PW" | encfs -S "$c" "$p" >>"$log" 2>&1
  if manifest "$p" | cmp -s - "$OUT/$name/manifest"; then
    echo "$name: ok, $(wc -l < "$OUT/$name/manifest") entries"
  else
    echo "$name: FAILED, C++ reads back something else"
    manifest "$p" | diff - "$OUT/$name/manifest" | head
  fi
  unmount "$p"
}

make_vol std standard
make_vol paranoia paranoia
make_vol nochain standard chainedNameIV=0
make_vol mac8 standard blockMACBytes=8
make_vol mac8-rand standard blockMACBytes=8 blockMACRandBytes=8
make_vol noholes standard allowHoles=0
make_vol block4096 standard blockSize=4096
make_vol extiv standard externalIVChaining=1
make_vol noheader standard uniqueIV=0
make_vol noheader-mac standard uniqueIV=0 blockMACBytes=8
make_vol noheader-nochain standard uniqueIV=0 chainedNameIV=0
# No header with external IV chaining: C++ never writes this itself (expert
# mode doesn't ask about chaining without per-file IVs), but reads it.
make_vol noheader-extiv standard uniqueIV=0 externalIVChaining=1
make_vol noheader-extiv-paranoia paranoia uniqueIV=0

# Expert mode answers, in prompt order: x (expert), cipher, key size, block
# size, name encoding, filename IV chaining, per-file IVs, [IV header
# chaining, asked only with per-file IVs], block MACs, random MAC bytes,
# holes.
#
# AES 128, 2048-byte blocks, Stream names, no per-file IV.
EXPERT_ANSWERS=$'x\n1\n128\n2048\n4\ny\nn\n\n\n\n\n\n'
make_vol expert-noheader expert
if grep -q "header chaining" "$OUT/expert-noheader.log" 2>/dev/null; then
  echo "expert-noheader: NOTE, C++ asked about IV header chaining without per-file IVs"
fi
# Blowfish 160, 512-byte blocks, Block32 names. C++ 1.9.5 on Ubuntu 26.04
# segfaults creating it (OpenSSL 3 keeps Blowfish in the legacy provider).
EXPERT_ANSWERS=$'x\n2\n160\n512\n2\ny\ny\nn\nn\n0\ny\n'
make_vol expert-blowfish expert

cat "$OUT/encfs-version"
