VERSION=0.9.8.10
GIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# FULL_VERSION comes from debian/changelog's top entry, so the package and
# the binaries report the same version: VERSION-N+HASH for a dev-N entry,
# VERSION+HASH for a release.
FULL_VERSION=$(shell \
	top=$$(grep -m1 '^dnshived' debian/changelog); \
	if echo "$$top" | grep -q 'dev-[0-9]'; then \
		dev=$$(echo "$$top" | sed -E 's/.*dev-([0-9]+).*/\1/'); \
		echo "$(VERSION)-$$dev+$(GIT_HASH)"; \
	else \
		echo "$(VERSION)+$(GIT_HASH)"; \
	fi)

build:
	mkdir -p builds
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived ./cmd/dnshived
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-status ./cmd/dnshived-status
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-validate ./cmd/dnshived-validate
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-top ./cmd/dnshived-top
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-helper ./cmd/dnshived-helper
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-dhcp-probe ./cmd/dnshived-dhcp-probe
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-web ./cmd/dnshived-web
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-web-helper ./cmd/dnshived-web-helper
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-probe ./cmd/dnshived-probe
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-probe-helper ./cmd/dnshived-probe-helper
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-relay ./cmd/dnshived-relay
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-dhcp-lease-hook ./cmd/dnshived-dhcp-lease-hook
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(FULL_VERSION)" -o builds/dnshived-preflight ./cmd/dnshived-preflight

check-config: build
	./builds/dnshived --check-config --config cluster.json.example

# Unsigned, binary-only .deb built from the working tree; output lands one
# directory up (dpkg-buildpackage convention).
deb:
	dpkg-buildpackage -us -uc -b

deb-check: deb
	lintian ../dnshived_*.deb

# .rpm packages (dnshived + dnshived-probe) via rpm/dnshived.spec;
# tools/rpm-version.sh derives Version/Release from debian/changelog.
# The source tarball is the working tree as a temporary git tree (a
# separate index, so the real one is untouched) + `git archive`: tracked
# changes anywhere, and new files under the source directories only, so a
# stray directory in the checkout never ends up in the package.
RPM_TOPDIR := $(CURDIR)/rpmbuild
.PHONY: rpm rpm-check
rpm:
	@eval "$$(tools/rpm-version.sh)"; \
	mkdir -p $(RPM_TOPDIR)/SOURCES $(RPM_TOPDIR)/SPECS $(RPM_TOPDIR)/BUILD $(RPM_TOPDIR)/BUILDROOT $(RPM_TOPDIR)/RPMS $(RPM_TOPDIR)/SRPMS; \
	rm -f $(RPM_TOPDIR)/RPMS/*/dnshived-*.rpm; \
	TMPIDX=$$(mktemp); cp "$$(git rev-parse --git-path index)" "$$TMPIDX"; \
	GIT_INDEX_FILE="$$TMPIDX" git add -u && GIT_INDEX_FILE="$$TMPIDX" git add -A -- $(wildcard cmd internal rpm debian tools); TREEISH=$$(GIT_INDEX_FILE="$$TMPIDX" git write-tree); rm -f "$$TMPIDX"; \
	git archive --format=tar --prefix=dnshived-$$RPM_VERSION/ $$TREEISH \
		| gzip > $(RPM_TOPDIR)/SOURCES/dnshived-$$RPM_VERSION.tar.gz; \
	echo "Building dnshived $$RPM_VERSION-$$RPM_RELEASE ..."; \
	rpmbuild --nodeps --define "_topdir $(RPM_TOPDIR)" \
	         --define "rpm_version $$RPM_VERSION" \
	         --define "rpm_release $$RPM_RELEASE" \
	         --define "full_version $(FULL_VERSION)" \
	         -bb rpm/dnshived.spec
	@echo "NOTE: built with --nodeps — this project's own reference build"
	@echo "host is Debian, which has no rpm-tracked 'golang' package to"
	@echo "satisfy the spec's real BuildRequires check. A real RHEL/"
	@echo "CentOS/Rocky build host resolves this normally."

# Lab-only profiling build. It compiles the labprofile tool (a CPU/heap/goroutine
# profile written on SIGWINCH, and only when /etc/dnshived/lab-profile.enable
# exists) into the daemon, the DNS relay and the web UI, and renames the packages so they
# cannot be mistaken for a release. Never ship these; make release-guard
# refuses them.
.PHONY: lab-deb lab-rpm release-guard
lab-deb:
	rm -f ../dnshived_*_amd64.deb ../dnshived_*_amd64.LAB-PROFILE.deb
	GOFLAGS=-tags=labprofile $(MAKE) deb
	@f=$$(ls -t ../dnshived_*_amd64.deb | head -1); mv "$$f" "$${f%.deb}.LAB-PROFILE.deb"; echo "built $${f%.deb}.LAB-PROFILE.deb (lab only, never ship)"

lab-rpm:
	GOFLAGS=-tags=labprofile $(MAKE) rpm
	@for f in $(RPM_TOPDIR)/RPMS/*/dnshived-*.rpm; do mv "$$f" "$${f%.rpm}.LAB-PROFILE.rpm"; echo "built $${f%.rpm}.LAB-PROFILE.rpm (lab only, never ship)"; done

# Run before every release upload: fails when a package or binary carries the
# lab profiling tool.
release-guard:
	tools/release-guard.sh

rpm-check: rpm
	rpmlint $(RPM_TOPDIR)/RPMS/*/dnshived-*.rpm || true
