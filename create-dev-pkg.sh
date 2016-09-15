mkdir build
cd build
cmake .. $@
make -j4
sudo checkinstall --install=no \
  --pkgname="encfs" \
  --provides="encfs"

