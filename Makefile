# jwkit: one entry point for both implementations.
#
#   make test         unit tests, Go (with the race detector) and TypeScript
#   make fuzz         Go fuzzers for FUZZTIME each, then the TS property tests
#   make conformance  run both conformance runners, diff them, check the README matrix
#   make differential run MUTATIONS random tokens (seed SEED) through both and diff
#   make examples     build both example servers and smoke-test them end to end
#   make cover        coverage for both, failing below 90%
#   make lint         go vet, staticcheck, tsc, eslint
#   make bench        Go benchmarks for cached verification
#   make fixtures     regenerate conformance/fixtures.json
#   make all          lint + test + cover + conformance

FUZZTIME      ?= 30s
MUTATIONS     ?= 5000
SEED          ?= 1
COVER_MIN     ?= 90
STATICCHECK   ?= honnef.co/go/tools/cmd/staticcheck@v0.8.1
RESULTS       := conformance/results

.PHONY: all test test-go test-ts fuzz fuzz-go fuzz-ts conformance differential fixtures examples cover cover-go cover-ts lint lint-go lint-ts bench ts-deps clean

all: lint test cover conformance

# ---- tests -----------------------------------------------------------------

test: test-go test-ts

test-go:
	cd go && go test -race -count=1 ./...

test-ts: ts-deps
	cd ts && npm test

# npm ci only when node_modules is missing or older than the lockfile.
ts-deps: ts/node_modules/.package-lock.json

ts/node_modules/.package-lock.json: ts/package-lock.json
	cd ts && npm ci
	@touch $@

# ---- fuzzing ---------------------------------------------------------------

fuzz: fuzz-go fuzz-ts

# go test accepts one -fuzz target per invocation.
fuzz-go:
	cd go && go test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) .
	cd go && go test -run='^$$' -fuzz='^FuzzVerify$$' -fuzztime=$(FUZZTIME) .

fuzz-ts: ts-deps
	cd ts && npx vitest run test/property.test.ts

# ---- conformance -----------------------------------------------------------

# Three checks, each of which fails the target:
#   1. each runner's results equal the fixture expectations (runner exit status)
#   2. the two result files are byte-identical (diff)
#   3. the matrix in the README is the one these results render to (report)
conformance: ts-deps
	cd conformance && go run . -check
	@mkdir -p $(RESULTS)
	cd conformance && go run ./run_go -fixtures fixtures.json -out results/go.json
	cd ts && npx tsx ../conformance/run_ts/run.mts --fixtures ../conformance/fixtures.json --out ../$(RESULTS)/ts.json
	diff -u $(RESULTS)/go.json $(RESULTS)/ts.json
	cd conformance && go run ./report -readme ../README.md $(REPORT_FLAGS)

# Differential testing: tokens nobody wrote an expectation for. The two
# runners' results are compared with each other; see conformance/mutate.go.
differential: ts-deps
	@mkdir -p $(RESULTS)
	cd conformance && go run . -mutations $(MUTATIONS) -seed $(SEED) -out results/mutations.json
	cd conformance && go run ./run_go -fixtures results/mutations.json -out results/mutations-go.json
	cd ts && npx tsx ../conformance/run_ts/run.mts --fixtures ../$(RESULTS)/mutations.json --out ../$(RESULTS)/mutations-ts.json
	diff -u $(RESULTS)/mutations-go.json $(RESULTS)/mutations-ts.json
	@echo "Go and TypeScript agree on all $(MUTATIONS) mutations (seed $(SEED))"

fixtures:
	cd conformance && go run .

# ---- examples --------------------------------------------------------------

examples: ts-deps
	cd ts && npm run build
	cd examples/express-server && npm install --no-audit --no-fund
	./examples/smoke.sh

# ---- coverage --------------------------------------------------------------

cover: cover-go cover-ts

cover-go:
	cd go && go test -count=1 -coverprofile=coverage.out ./...
	@cd go && go tool cover -func=coverage.out | awk -v min=$(COVER_MIN) '\
		/^total:/ { sub("%", "", $$3); pct = $$3 } \
		END { printf "Go statement coverage: %s%% (minimum %s%%)\n", pct, min; exit (pct + 0 < min + 0) }'

# The thresholds live in ts/vitest.config.ts.
cover-ts: ts-deps
	cd ts && npm run cover

# ---- static checks ---------------------------------------------------------

lint: lint-go lint-ts

lint-go:
	cd go && go vet ./... && go run $(STATICCHECK) ./...
	cd conformance && go vet ./... && go run $(STATICCHECK) ./...
	cd examples/gin-server && go vet ./... && go run $(STATICCHECK) ./...
	@test -z "$$(gofmt -l go conformance examples)" || { echo "gofmt needed:"; gofmt -l go conformance examples; exit 1; }

# The Express example depends on the package by path, so it type-checks
# against the built declarations.
lint-ts: ts-deps
	cd ts && npm run typecheck && npm run lint && npm run build
	cd examples/express-server && npm install --no-audit --no-fund && npx tsc --noEmit

# ---- benchmarks ------------------------------------------------------------

bench:
	cd go && go test -run='^$$' -bench=. -benchmem -count=1 .

clean:
	rm -rf $(RESULTS) go/coverage.out ts/coverage ts/dist
