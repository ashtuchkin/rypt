#!/bin/bash -ex

local TARGET=
if [ $TRAVIS_OS_NAME = linux ]; then
    TARGET=x86_64-unknown-linux-musl
    sort=sort
else
    TARGET=x86_64-apple-darwin
    sort=gsort  # for `sort --sort-version`, from brew's coreutils.

    # Builds for iOS are done on OSX, but require the specific target to be
    # installed.
    case $TARGET in
        x86_64-apple-ios)
            rustup target install x86_64-apple-ios
            ;;
    esac
fi

rustup target add $TARGET

#
#  # This fetches latest stable release
#  local tag=$(git ls-remote --tags --refs --exit-code https://github.com/japaric/cross \
#                     | cut -d/ -f3 \
#                     | grep -E '^v[0.1.0-9.]+$' \
#                     | $sort --version-sort \
#                     | tail -n1)
#  curl -LSfs https://japaric.github.io/trust/install.sh | \
#      sh -s -- \
#         --force \
#         --git japaric/cross \
#         --tag $tag \
#         --target $target
