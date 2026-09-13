SWIFT ?= swift
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all build release setup test test-full integration check install clean

# Debug is the normal development build and keeps repeated CLI runs fast.
all: build

build:
	$(SWIFT) build

release:
	$(SWIFT) build -c release

setup:
	@./setup.sh
	@$(SWIFT) build --quiet
	@.build/debug/liter8 setup

test:
	# Keep the normal edit/test loop responsive. Kernel oracles are intentionally
	# separated because six full-image scans take several minutes.
	$(SWIFT) test --skip KernelResolverTests

test-full:
	# Use optimized resolvers for the expensive exact-kernel oracle suite.
	# The first release build is costly; subsequent runs reuse SwiftPM's cache.
	$(SWIFT) test -c release

# Exercise the real CLI handoff without requiring a multi-gigabyte IPSW.
integration: build
	bash Tests/fw-workflow-integration.sh
	python3 Tests/ipsw-robustness-integration.py
	python3 Tests/python-workflow-tests.py

check: test-full integration

# The executable and immutable workflow resources use the layout understood by
# Liter8Resources: <prefix>/bin/liter8 and <prefix>/share/liter8/...
install: release
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(PREFIX)/share/liter8/scripts" "$(DESTDIR)$(PREFIX)/share/liter8/tools" "$(DESTDIR)$(PREFIX)/share/liter8/payloads" "$(DESTDIR)$(PREFIX)/share/liter8/device"
	install -m 755 .build/release/liter8 "$(DESTDIR)$(PREFIX)/bin/liter8"
	install -m 644 requirements.txt "$(DESTDIR)$(PREFIX)/share/liter8/requirements.txt"
	install -m 644 scripts/*.py scripts/README.md "$(DESTDIR)$(PREFIX)/share/liter8/scripts/"
	if test -d tools; then cp -R tools/. "$(DESTDIR)$(PREFIX)/share/liter8/tools/"; fi
	if test -d payloads; then cp -R payloads/. "$(DESTDIR)$(PREFIX)/share/liter8/payloads/"; fi
	if test -d device; then cp -R device/. "$(DESTDIR)$(PREFIX)/share/liter8/device/"; fi

clean:
	$(SWIFT) package clean
