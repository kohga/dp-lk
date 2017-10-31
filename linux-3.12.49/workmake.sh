#!/bin/sh

make -j4
make modules
make modules_install
make install
