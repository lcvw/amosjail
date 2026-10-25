#!/bin/sh
# Push the tree to the test Mac and build amosjail-enter there.
# AMOSJAIL_MAC=user@host (default: the shared test Mac).
set -e
MAC=${AMOSJAIL_MAC:-liamwisehart@100.78.179.107}
cd "$(dirname "$0")/.."
git ls-files -co --exclude-standard | tar -cf - -T - | ssh "$MAC" 'rm -rf amosjail.new && mkdir amosjail.new && tar -xf - -C amosjail.new && rm -rf amosjail && mv amosjail.new amosjail && make -s -C amosjail/enter'
