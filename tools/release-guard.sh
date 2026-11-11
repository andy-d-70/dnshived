#!/bin/bash
# Refuses a release that carries the lab-only profiling tool.
#
# Scans the packages and binaries given as arguments (default: the packages one
# directory up, the rpm build output and builds/) for the build marker of the
# labprofile tool and for LAB-PROFILE in a file name. Run it before every
# release upload (make release-guard).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

MARKER="DNSHIVED-LAB-PROFILE""-BUILD"
bad=0
checked=0

if [ $# -gt 0 ]; then
	files=("$@")
else
	shopt -s nullglob
	files=(../dnshived_*.deb ../dnshived-probe_*.deb rpmbuild/RPMS/*/dnshived-*.rpm builds/*)
fi

# The extracted bytes go to a temporary file and are searched in full: a
# grep -q at the end of a pipeline would stop at the first match, the writer
# would die of SIGPIPE and pipefail would report "no match".
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# need_bytes refuses an empty extraction: a broken package must not count as
# clean. Both helpers run in the main shell so that an exit really stops the run.
need_bytes() {
	[ -s "$tmp" ] || { echo "release-guard: nothing could be extracted from $1" >&2; exit 2; }
}
has_marker() {
	[ "$(grep -a -c -- "$MARKER" "$tmp" || true)" -gt 0 ]
}

for f in "${files[@]}"; do
	[ -f "$f" ] || continue
	checked=$((checked + 1))
	case "$f" in
	*LAB-PROFILE*) echo "REFUSED: $f is named as a lab profiling build"; bad=1; continue ;;
	esac
	case "$f" in
	*.deb)
		command -v dpkg-deb >/dev/null || { echo "dpkg-deb is needed to scan $f"; exit 2; }
		dpkg-deb --fsys-tarfile "$f" | tar -xO >"$tmp" 2>/dev/null || { echo "release-guard: cannot read $f" >&2; exit 2; }
		need_bytes "$f"; if has_marker; then hit=1; else hit=0; fi ;;
	*.rpm)
		command -v rpm2cpio >/dev/null && command -v cpio >/dev/null || { echo "rpm2cpio and cpio are needed to scan $f"; exit 2; }
		rpm2cpio "$f" | cpio -i --to-stdout --quiet >"$tmp" 2>/dev/null || { echo "release-guard: cannot read $f" >&2; exit 2; }
		need_bytes "$f"; if has_marker; then hit=1; else hit=0; fi ;;
	*)
		cp "$f" "$tmp"
		need_bytes "$f"; if has_marker; then hit=1; else hit=0; fi ;;
	esac
	if [ "$hit" = 1 ]; then
		echo "REFUSED: $f contains the lab profiling tool"
		bad=1
	fi
done

if [ "$checked" = 0 ]; then
	echo "release-guard: nothing to check (no packages or binaries found)"
	exit 2
fi
if [ "$bad" = 1 ]; then
	echo "release-guard: FAILED, do not release these files"
	exit 1
fi
echo "release-guard: $checked file(s) clean"
