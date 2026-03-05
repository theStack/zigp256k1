#!/usr/bin/env bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/zigp256k1
