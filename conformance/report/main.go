// Command report compares what the Go and TypeScript runners produced with
// each other and with the fixture expectations, and renders the result as the
// conformance matrix shown in the README.
//
//	go run ./report                       print the matrix
//	go run ./report -readme ../README.md  rewrite the matrix block in the README
//	go run ./report -readme ../README.md -check
//	                                      fail if the README's matrix is stale
//
// It exits with status 1 if any case differs between the two implementations
// or from its expectation, so the matrix can only ever be generated from an
// all-identical run.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	startMarker = "<!-- conformance:start -->"
	endMarker   = "<!-- conformance:end -->"
)

type fixtureCase struct {
	Name   string `json:"name"`
	About  string `json:"about"`
	Expect string `json:"expect"`
}

type result struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

func main() {
	fixturesPath := flag.String("fixtures", "fixtures.json", "path of the fixtures file")
	goPath := flag.String("go", "results/go.json", "results written by run_go")
	tsPath := flag.String("ts", "results/ts.json", "results written by run_ts")
	readme := flag.String("readme", "", "README whose matrix block should be rewritten (or checked)")
	check := flag.Bool("check", false, "with -readme: verify the block is current instead of rewriting it")
	flag.Parse()

	if err := run(*fixturesPath, *goPath, *tsPath, *readme, *check); err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		os.Exit(1)
	}
}

func run(fixturesPath, goPath, tsPath, readme string, check bool) error {
	var fx struct {
		Cases []fixtureCase `json:"cases"`
	}
	if err := readJSON(fixturesPath, &fx); err != nil {
		return err
	}
	var goResults, tsResults []result
	if err := readJSON(goPath, &goResults); err != nil {
		return err
	}
	if err := readJSON(tsPath, &tsResults); err != nil {
		return err
	}
	if len(goResults) != len(fx.Cases) || len(tsResults) != len(fx.Cases) {
		return fmt.Errorf("fixtures have %d cases but Go reported %d and TypeScript %d",
			len(fx.Cases), len(goResults), len(tsResults))
	}

	var problems []string
	for i, c := range fx.Cases {
		g, t := goResults[i], tsResults[i]
		if g.Name != c.Name || t.Name != c.Name {
			return fmt.Errorf("case %d: results are out of order (%q, %q, %q)", i, c.Name, g.Name, t.Name)
		}
		if g.Result != t.Result {
			problems = append(problems, fmt.Sprintf("%s: Go says %s, TypeScript says %s", c.Name, g.Result, t.Result))
		}
		if g.Result != c.Expect || t.Result != c.Expect {
			problems = append(problems, fmt.Sprintf("%s: expected %s, Go says %s, TypeScript says %s", c.Name, c.Expect, g.Result, t.Result))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}

	matrix := render(fx.Cases, goResults, tsResults)
	if readme == "" {
		fmt.Print(matrix)
		return nil
	}
	return updateReadme(readme, matrix, check)
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// render is only reached when every result is identical, so the Go and
// TypeScript columns are printed from their own data but are known to match.
func render(cases []fixtureCase, goResults, tsResults []result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d cases, %d identical results across the fixture expectation, Go and TypeScript.\n\n", len(cases), len(cases))

	// Summary by expected result, in order of first appearance.
	var order []string
	count := map[string]int{}
	for _, c := range cases {
		if count[c.Expect] == 0 {
			order = append(order, c.Expect)
		}
		count[c.Expect]++
	}
	b.WriteString("| Expected result | Cases | Go agrees | TypeScript agrees |\n|---|---:|---:|---:|\n")
	for _, expect := range order {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d |\n", expect, count[expect], count[expect], count[expect])
	}

	fmt.Fprintf(&b, "\n<details>\n<summary>All %d cases</summary>\n\n", len(cases))
	b.WriteString("| Case | What the token is | Go | TypeScript |\n|---|---|---|---|\n")
	for i, c := range cases {
		about := strings.ReplaceAll(c.About, "|", `\|`)
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | `%s` |\n", c.Name, about, goResults[i].Result, tsResults[i].Result)
	}
	b.WriteString("\n</details>\n")
	return b.String()
}

func updateReadme(path, matrix string, check bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	start := bytes.Index(raw, []byte(startMarker))
	end := bytes.Index(raw, []byte(endMarker))
	if start < 0 || end < start {
		return fmt.Errorf("%s has no %s ... %s block", path, startMarker, endMarker)
	}
	var updated bytes.Buffer
	updated.Write(raw[:start+len(startMarker)])
	updated.WriteString("\n")
	updated.WriteString(matrix)
	updated.Write(raw[end:])

	if bytes.Equal(updated.Bytes(), raw) {
		fmt.Printf("%s: conformance matrix is up to date\n", path)
		return nil
	}
	if check {
		return fmt.Errorf("%s: conformance matrix is stale; run `make conformance` and commit the result", path)
	}
	fmt.Printf("%s: conformance matrix updated\n", path)
	return os.WriteFile(path, updated.Bytes(), 0o644)
}
