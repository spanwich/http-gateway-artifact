.PHONY: qemu-test sel4-build fstar-verify host-tests methodology-tests all clean help

help:
	@echo "Available targets:"
	@echo "  make qemu-test         - Run 7 integration tests with prebuilt images (~2 min)"
	@echo "  make sel4-build        - Rebuild from seL4 source (~30-60 min, ~8GB disk)"
	@echo "  make fstar-verify      - Re-verify F* proofs and re-extract C (~10-15 min)"
	@echo "  make host-tests        - Run host-compilable tests (gcc only, no Docker)"
	@echo "  make methodology-tests - Run methodology validation tests (gcc only)"
	@echo "  make all               - Run host-tests + qemu-test"

qemu-test:
	docker build -t sel4-gw-runner docker/qemu-runner/
	@echo "=== Starting QEMU gateway ==="
	docker run --rm -d --name sel4-gw-test \
	    -v $(CURDIR)/prebuilt:/prebuilt:ro \
	    sel4-gw-runner /usr/local/bin/start-gateway-slirp.sh
	@echo "=== Running integration tests ==="
	@docker exec sel4-gw-test /usr/local/bin/run-tests.sh ; \
	    EXIT=$$? ; \
	    docker stop sel4-gw-test 2>/dev/null || true ; \
	    exit $$EXIT

sel4-build:
	docker build -t sel4-gw-builder -f docker/sel4-builder/Dockerfile .
	docker run --rm \
	    -v $(CURDIR)/src:/src:ro \
	    -v $(CURDIR)/prebuilt:/output \
	    sel4-gw-builder /build.sh

fstar-verify:
	docker build -t sel4-gw-fstar -f docker/fstar-verifier/Dockerfile .
	docker run --rm \
	    -v $(CURDIR)/verified:/workspace/verified:ro \
	    -v $(CURDIR)/specs:/workspace/specs:ro \
	    -v $(CURDIR)/test:/workspace/test:ro \
	    -v $(CURDIR)/src/components/include:/workspace/src/components/include:ro \
	    sel4-gw-fstar /verify.sh

host-tests:
	@echo "=== Pipeline tests (46 tests) ==="
	cd specs && make clean && make test
	@echo ""
	@echo "=== Production tests (46 tests) ==="
	cd test/production && make clean && make test
	@echo ""
	@echo "=== Rate limiter unit tests (8 tests) ==="
	cd test/unit && make clean && make test
	@echo ""
	@echo "=== All host tests passed ==="

methodology-tests:
	@echo "=== Methodology validation tests ==="
	cd test/methodology && $(MAKE) all
	@echo ""
	@echo "=== All methodology tests passed ==="

all: host-tests qemu-test

clean:
	cd specs && make clean 2>/dev/null || true
	cd test/production && make clean 2>/dev/null || true
	cd test/unit && make clean 2>/dev/null || true
	cd test/methodology && $(MAKE) clean 2>/dev/null || true
	docker rmi sel4-gw-runner sel4-gw-builder sel4-gw-fstar 2>/dev/null || true
