#!/bin/bash
# Derives the RPM Version/Release from debian/changelog's top entry, like
# FULL_VERSION for the .deb. RPM versions cannot contain - or ~, so a dev
# build becomes Release 0.devN.<hash> (sorts before release 1).
#
# Usage: eval "$(tools/rpm-version.sh)" sets RPM_VERSION/RPM_RELEASE.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION=$(grep '^VERSION=' Makefile | cut -d= -f2)
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
TOP=$(grep -m1 '^dnshived' debian/changelog)

if echo "$TOP" | grep -q 'dev-[0-9]'; then
    DEV=$(echo "$TOP" | sed -E 's/.*dev-([0-9]+).*/\1/')
    echo "RPM_VERSION=${VERSION}"
    echo "RPM_RELEASE=0.dev${DEV}.${GIT_HASH}"
else
    echo "RPM_VERSION=${VERSION}"
    echo "RPM_RELEASE=1.${GIT_HASH}"
fi
