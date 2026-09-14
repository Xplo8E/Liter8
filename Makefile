SWIFT ?= swift
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all build release setup test test-fixtures test-full test-e2e integration check install clean

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
	# Keep the normal edit/test loop responsive. Real-kernel fixture scans and
	# the deliberately duplicated production-wiring check have separate tiers.
	$(SWIFT) test --skip KernelFixtureTests --skip KernelEndToEndTests --skip ReleaseFixtureTests

test-fixtures:
	# Resolve each beta-4 and 24A435 component once per process. The tests still
	# verify exact offsets, preimages, replacements and complete output hashes.
	$(SWIFT) test -c release --filter KernelFixtureTests
	$(SWIFT) test -c release --filter ReleaseFixtureTests
	python3 Tests/apply-records-fixture-tests.py

test-full:
	# Run fast tests plus the cached real-kernel fixtures. The uncached composite
	# production check is intentionally reserved for test-e2e.
	$(SWIFT) test -c release --skip KernelEndToEndTests

test-e2e:
	# Re-run the production composite resolver without the fixture cache. This is
	# expensive by design and belongs in release or resolver-change validation.
	$(SWIFT) test -c release --filter KernelEndToEndTests

# Exercise the real CLI handoff without requiring a multi-gigabyte IPSW.
integration: build
	bash Tests/fw-workflow-integration.sh
	python3 Tests/ipsw-robustness-integration.py
	python3 Tests/python-workflow-tests.py

check: test-full test-e2e integration

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
