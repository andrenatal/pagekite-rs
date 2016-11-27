#!/bin/sh
set +x +e
cargo clean
make -C libpagekite clean
rm libpagekite/configure
