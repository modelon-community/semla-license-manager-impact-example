#! /bin/bash
set -euo pipefail

JANSSON_ARCHIVE_FILENAME="jansson-1.0.4.zip"
LIBJWT_ARCHIVE_FILENAME="SemlaLibJWT-1.0.14-linux64-gcc485.zip"
SEMLAOPENSSL_ARCHIVE_FILENAME="SemlaOpenSSL-1.3.1-linux64-gcc850.zip"

if [ -z ${1:-} ]; then
    echo "usage: $0 <VERSION>"
    exit 1;
fi

VERSION=$1


if ! [ -f ${JANSSON_ARCHIVE_FILENAME} ]; then
    echo "error: file not found: JANSSON_ARCHIVE_FILENAME=${JANSSON_ARCHIVE_FILENAME}"
    exit 1
fi
if ! [ -f ${LIBJWT_ARCHIVE_FILENAME} ]; then
    echo "error: file not found: LIBJWT_ARCHIVE_FILENAME=${LIBJWT_ARCHIVE_FILENAME}"
    exit 1
fi
if ! [ -f ${SEMLAOPENSSL_ARCHIVE_FILENAME} ]; then
    echo "error: file not found: SEMLAOPENSSL_ARCHIVE_FILENAME=${SEMLAOPENSSL_ARCHIVE_FILENAME}"
    exit 1
fi

# If the files are not already in a git repo, create a new local git repo on the fly.
if ! [ -d .git ]; then
    echo "info: files are not already in a git repo, creating a new local git repo on the fly"
    git init
    git add .
    git commit -m "first commit"
fi

if ! git diff --quiet; then
    echo "error: uncommitted changes"
    exit 1
fi
if ! git diff --quiet --staged; then
    echo "error: uncommitted staged changes"
    exit 1
fi

git archive \
    --output=semla-license-manager-impact-example-${VERSION}.zip \
    --add-file=${JANSSON_ARCHIVE_FILENAME} \
    --add-file=${LIBJWT_ARCHIVE_FILENAME} \
    --add-file=${SEMLAOPENSSL_ARCHIVE_FILENAME} \
    HEAD

TAG=v${VERSION}

git tag ${TAG}

if git ls-remote --exit-code origin >/dev/null; then
    git push origin ${TAG}
else
    echo "info: no remote 'origin' found. skipping pushing the tag to 'origin'"
fi
