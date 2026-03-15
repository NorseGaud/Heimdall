#!/usr/bin/env bash
set -exo pipefail

brew install cmake libusb qt@5

cmake . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DQt5Widgets_DIR=/opt/homebrew/opt/qt@5/lib/cmake/Qt5Widgets

export LIBRARY_PATH=/opt/homebrew/lib

make
sudo make install