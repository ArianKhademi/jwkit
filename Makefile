# jwkit: one entry point for both implementations.
#
#   make test         unit tests, Go (with the race detector) and TypeScript
#   make fuzz         Go fuzzers for FUZZTIME each, then the TS property tests
#   make conformance  run both conformance runners, diff them, check the README matrix
#   make cover        coverage for both, failing below 90%
#   make lint         go vet, staticcheck, tsc, eslint
#   make bench        Go benchmarks for cached verification
#   make fixtures     regenerate conformance/fixtures.json
#   make all          lint + test + cover + conformance

FUZZTIME      ?= 30s
COVER_MIN     ?= 90
STATICCHECK   ?= honnef.co/go/tools/cmd/staticcheck@v0.8.1
RESULTS       := conformance/results

.PHONY: all test test-go test-ts fuzz fuzz-go fuzz-ts conformance fixtures cover cover-go cover-ts lint lint-go lint-ts bench ts-deps clean

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

fixtures:
	cd conformance && go run .

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

lint-ts: ts-deps
	cd ts && npm run typecheck && npm run lint
	cd examples/express-server && npm install --no-audit --no-fund && npx tsc --noEmit

# ---- benchmarks ------------------------------------------------------------

bench:
	cd go && go test -run='^$$' -bench=. -benchmem -count=1 .

clean:
	rm -rf $(RESULTS) go/coverage.out ts/coverage ts/dist
