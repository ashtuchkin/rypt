#!/bin/bash -ex

: "${PROJECT_NAME:?env var is required}"
: "${TRAVIS_TAG:?env var is required}"
: "${FRIENDLY_TARGET_NAME:?env var is required}"
: "${TARGET:?env var is required}"

# Assume we've built the target in the previous steps.
# This requires skip_cleanup: true option.
# Also current working directory for this whole script is the main repo directory.

# Deployment base folder relative to main repo directory. All contents of this directory will be uploaded to GitHub releases.
DEPLOYMENT_DIR="deployment"
rm -rf "$DEPLOYMENT_DIR"
mkdir "$DEPLOYMENT_DIR"

# Create a per-target directory where we'll put the actual files
TARGET_DIR="$DEPLOYMENT_DIR/$FRIENDLY_TARGET_NAME"
mkdir "$TARGET_DIR"

# Copy main binary to the staging directory and make it smaller
cp "target/$TARGET/release/$PROJECT_NAME" "$TARGET_DIR/"
RYPT_BINARY="$TARGET_DIR/$PROJECT_NAME"
strip "$RYPT_BINARY"

# Sanity check that git tag corresponds to binary version
VERSION=$("$RYPT_BINARY" --version | head -n 1)
if [[ "$VERSION" != "$PROJECT_NAME ${TRAVIS_TAG#v}" ]]; then
  echo "Error: Binary version \"$VERSION\" does not correspond to tag \"$TRAVIS_TAG\""
  exit 1
fi

# Calculate SHA256 hash of the file(s) in the staging directory.
(cd "$TARGET_DIR" && sha256sum -b -- * > SHA256SUMS)

# Print contents of the archive and the sha sums
ls -l "$TARGET_DIR/"
cat "$TARGET_DIR/SHA256SUMS"
