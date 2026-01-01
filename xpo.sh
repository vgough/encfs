#!/bin/sh -e

pot=po/encfs.pot
langs=`grep -v '#' po/LINGUAS`

xgettext --language=Rust "--keyword=i18n_format!" "--keyword=i18n_nformat!:1,2" --from-code=UTF-8 -o $pot src/*.rs

for s in $langs; do
        msgmerge --update --backup=none po/$s.po $pot
done
