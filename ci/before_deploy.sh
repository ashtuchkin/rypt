#!/bin/bash -ex

: "${PROJECT_NAME:?env var is required}"
: "${TRAVIS_TAG:?env var is required}"
: "${FRIENDLY_TARGET_NAME:?env var is required}"
: "${TARGET:?env var is required}"

# Assume we've built the target in the previous steps.
# This requires skip_cleanup: true option.
# Also current working directory for this whole script is the main repo directory.

fill_tarball_contents() {
  local STAGING_DIR="$1"

  # Copy main binary to the staging directory and make it smaller
  cp "target/$TARGET/release/$PROJECT_NAME" "$STAGING_DIR/"
  local RYPT_BINARY="$STAGING_DIR/$PROJECT_NAME"
  strip "$RYPT_BINARY"

  # Sanity check that git tag corresponds to binary version
  local VERSION=$("$RYPT_BINARY" --version | head -n 1)
  if [[ "$VERSION" != "$PROJECT_NAME ${TRAVIS_TAG#v}" ]]; then
    echo "Binary version \"$VERSION\" does not correspond to tag \"$TRAVIS_TAG\""
    exit 1
  fi

  # Copy readme and license
  cp {README.md,LICENSE} "$STAGING_DIR/"

  # Print contents of the archive
  ls -l "$STAGING_DIR/"
}

create_tarball() {
  local DEPLOYMENT_DIR="$1"
  local NAME="$2"

  # Ensure we're not reusing deployment directory
  rm -rf "$DEPLOYMENT_DIR"

  # Create a staging directory to keep the future tarball contents
  local STAGING_DIR="$DEPLOYMENT_DIR/$NAME"
  mkdir -p "$STAGING_DIR"

  fill_tarball_contents "$STAGING_DIR"

  # Create the tarball in the deployment directory
  (cd "$DEPLOYMENT_DIR" && tar czf "$NAME.tar.gz" "$NAME")
  ls -l "$DEPLOYMENT_DIR/$NAME.tar.gz"

  rm -rf "$STAGING_DIR"
}

# Name of the tarball and the folder inside the tarball
NAME="$PROJECT_NAME-$TRAVIS_TAG-$FRIENDLY_TARGET_NAME"

# Main folder to be used in deployment. This whole directory will be uploaded to GitHub releases.
DEPLOYMENT_DIR="deployment"

create_tarball "$DEPLOYMENT_DIR" "$NAME"