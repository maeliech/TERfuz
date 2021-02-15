#!/bin/bash

rm -rf build/ && CC=clang meson build && ninja -C build && mkdir build/fuzzing/out
