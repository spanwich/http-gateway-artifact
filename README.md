# seL4 HTTP Gateway Artifact

8-component XACML-aligned CAmkES pipeline on seL4 for x86\_64, implementing a formally verified HTTP gateway with bearer token authentication, EverParse-validated RBAC policy enforcement, and per-subject rate limiting.

## Requirements

- **Docker** (for QEMU tests, seL4 rebuild, F\* verification)
- **gcc + make** (for host-compilable tests, no Docker needed)
- Disk space: ~500MB (QEMU runner), ~10GB (seL4 rebuild), ~2GB (F\* verifier)

## Quick Start

### Run integration tests (~2 min, Docker)

```bash
make qemu-test
```

Boots the gateway in QEMU with prebuilt images and runs 7 curl-based tests:
1. `GET /api/status` without token → 401
2. `POST /api/login` (admin) → 200 + token
3. `GET /api/status` with token → 200
4. `GET /api/status` with bad token → 403
5. `POST /api/login` (operator) → 200
6. `PUT /api/policy` (admin) → 200
7. Rate limit exhaustion → 429

### Run host-compilable tests (~10s, no Docker)

```bash
make host-tests
```

Runs 100 tests with just `gcc` and `make`:
- 46 pipeline tests (RBAC lifecycle, scope bitfield, rate exhaustion)
- 46 production tests (same suite, independent build)
- 8 rate limiter unit tests

### Rebuild from seL4 source (~30-60 min, Docker)

```bash
make sel4-build
```

Syncs the seL4/CAmkES ecosystem, compiles all 8 components, produces kernel + CapDL images in `prebuilt/`. Uses `trustworthysystems/camkes:2025_05_22` base image.

### Re-verify F\* proofs (~10-15 min, Docker)

```bash
make fstar-verify
```

5-step pipeline:
1. Verify 8 F\* modules (type-check + proof obligations)
2. Extract to C via KreMLin
3. Run 6 unit test programs on extracted code
4. Regenerate EverParse validators from `RbacPolicy.3d` and diff against checked-in code
5. Run 46 pipeline tests

### Run methodology validation tests (~10s, no Docker)

```bash
make methodology-tests
```

188 tests across 4 batches validating paper claims (Batch A: RBAC+scale, B: bitmask/arithmetic/range, C: multi-session pipeline, D: partitioned verification).

## Directory Layout

| Directory | Contents |
|-----------|----------|
| `src/` | CAmkES source: 8 components, assembly, build files |
| `src/components/` | E1000Driver, TlsValidator, LwipProxy, FStarExtractor, Authenticator, RateLimiter, PolicyGate, ProtectedApp |
| `verified/` | 8 F\* source modules (1230 lines) + KreMLin-extracted C + 6 test harnesses |
| `specs/` | `RbacPolicy.3d` (240 lines) + EverParse-generated validators + pipeline test infrastructure |
| `test/` | Integration (7 QEMU), production (46), unit (8), methodology (188) |
| `docker/` | Three Dockerfiles: qemu-runner, sel4-builder, fstar-verifier |
| `prebuilt/` | Prebuilt seL4 kernel + CapDL loader for quick testing |

## Versions

| Component | Version |
|-----------|---------|
| EverParse | v2025.10.06 |
| seL4/CAmkES Docker | trustworthysystems/camkes:2025\_05\_22 |
| mbedTLS | 3.6.5 |
| HACL\* | Project Everest (vendored, Apache-2.0) |

## Manual Testing (Interactive)

Start the gateway interactively:

```bash
docker build -t sel4-gw-runner docker/qemu-runner/
docker run --rm -it -p 8443:8443 \
    -v $(pwd)/prebuilt:/prebuilt:ro \
    sel4-gw-runner /usr/local/bin/start-gateway-slirp.sh
```

From another terminal:

```bash
# Login
curl -sk -X POST -d '{"username":"admin","password":"admin456"}' \
    https://localhost:8443/api/login

# Use token
TOKEN="<token from login response>"
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/status
```

Exit QEMU: `Ctrl+A, X`.

## License

BSD-2-Clause. See `LICENSE` for details and third-party attributions.
