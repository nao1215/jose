package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
)

// These tests keep the published documentation honest. The cookbook
// (doc/cookbook.md) is the page readers copy commands from, so every shell
// block in it must be run, character for character, by the atago suite in
// e2e/atago/cookbook.atago.yaml. The reference page must list every flag the
// binary has.

const (
	cookbookPath     = "../doc/cookbook.md"
	cookbookSpecPath = "../e2e/atago/cookbook.atago.yaml"
	referencePath    = "../website/content/reference.md"
	cookbookIndex    = "Find a recipe by task"
)

// cookbookSection is one "## " section of the cookbook.
type cookbookSection struct {
	title  string
	blocks map[string][]string // fenced code blocks by info string
	body   string
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// parseCookbook splits the cookbook into its "## " sections and collects the
// fenced code blocks of each.
func parseCookbook(t *testing.T) []cookbookSection {
	t.Helper()
	var (
		sections []cookbookSection
		current  *cookbookSection
		fence    string
		block    []string
	)
	for _, line := range strings.Split(readDoc(t, cookbookPath), "\n") {
		if fence != "" {
			if line == "```" {
				current.blocks[fence] = append(current.blocks[fence], strings.Join(block, "\n"))
				fence, block = "", nil
				continue
			}
			block = append(block, line)
			continue
		}
		if title, ok := strings.CutPrefix(line, "## "); ok {
			sections = append(sections, cookbookSection{title: title, blocks: map[string][]string{}})
			current = &sections[len(sections)-1]
			continue
		}
		if current == nil {
			continue
		}
		if info, ok := strings.CutPrefix(line, "```"); ok && info != "" {
			fence = info
			continue
		}
		current.body += line + "\n"
	}
	if fence != "" {
		t.Fatalf("unterminated %s block in %s", fence, cookbookPath)
	}
	return sections
}

type cookbookSpec struct {
	Scenarios []struct {
		Name  string `yaml:"name"`
		Steps []struct {
			Run *struct {
				Command string `yaml:"command"`
				Shell   bool   `yaml:"shell"`
			} `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"scenarios"`
}

// shellCommandsBySection maps each cookbook section to the shell commands its
// scenarios run. A scenario belongs to the section its name starts with,
// followed by ": "; section titles may contain ": " themselves, so the longest
// matching title wins.
func shellCommandsBySection(t *testing.T) map[string][]string {
	t.Helper()
	var spec cookbookSpec
	if err := yaml.Unmarshal([]byte(readDoc(t, cookbookSpecPath)), &spec); err != nil {
		t.Fatal(err)
	}
	sections := parseCookbook(t)

	commands := map[string][]string{}
	for _, scenario := range spec.Scenarios {
		section := ""
		for _, s := range sections {
			if strings.HasPrefix(scenario.Name, s.title+": ") && len(s.title) > len(section) {
				section = s.title
			}
		}
		if section == "" {
			t.Errorf("scenario %q does not start with a cookbook section title and \": \"", scenario.Name)
			continue
		}
		// Register the section even when the scenario runs no shell step.
		if _, seen := commands[section]; !seen {
			commands[section] = nil
		}
		for _, step := range scenario.Steps {
			if step.Run != nil && step.Run.Shell {
				commands[section] = append(commands[section], strings.TrimRight(step.Run.Command, "\n"))
			}
		}
	}
	return commands
}

func TestCookbookEverySectionHasAScenario(t *testing.T) {
	t.Parallel()
	commands := shellCommandsBySection(t)

	var missing []string
	for _, section := range parseCookbook(t) {
		if section.title == cookbookIndex {
			continue
		}
		if _, ok := commands[section.title]; !ok {
			missing = append(missing, section.title)
		}
	}
	if len(missing) > 0 {
		t.Errorf("cookbook sections without an atago scenario: %s", strings.Join(missing, ", "))
	}
}

func TestCookbookEveryShellBlockIsRun(t *testing.T) {
	t.Parallel()
	commands := shellCommandsBySection(t)

	for _, section := range parseCookbook(t) {
		run := map[string]bool{}
		for _, command := range commands[section.title] {
			run[command] = true
		}
		for _, block := range section.blocks["shell"] {
			if !run[block] {
				t.Errorf("section %q: this shell block is not run verbatim by any of its scenarios in %s:\n%s",
					section.title, cookbookSpecPath, block)
			}
		}
	}
}

func TestCookbookJSONBlocksParse(t *testing.T) {
	t.Parallel()
	for _, section := range parseCookbook(t) {
		for _, block := range section.blocks["json"] {
			if !json.Valid([]byte(block)) {
				t.Errorf("section %q: invalid JSON block:\n%s", section.title, block)
			}
		}
	}
}

// TestCookbookIndexLinksResolve checks the task table points at real sections,
// using the anchors Hugo and GitHub generate from the headings.
func TestCookbookIndexLinksResolve(t *testing.T) {
	t.Parallel()
	anchors := map[string]bool{}
	var index cookbookSection
	for _, section := range parseCookbook(t) {
		anchors[headingAnchor(section.title)] = true
		if section.title == cookbookIndex {
			index = section
		}
	}

	links := regexp.MustCompile(`\]\(#([^)]+)\)`).FindAllStringSubmatch(readDoc(t, cookbookPath), -1)
	if len(links) == 0 {
		t.Fatal("the cookbook has no in-page links")
	}
	for _, link := range links {
		if !anchors[link[1]] {
			t.Errorf("link to #%s has no matching section", link[1])
		}
	}
	if strings.Count(index.body, "](#") != len(anchors)-1 {
		t.Errorf("the task table links %d sections, the cookbook has %d", strings.Count(index.body, "](#"), len(anchors)-1)
	}
}

// headingAnchor mirrors the heading IDs Hugo (Goldmark) and GitHub generate:
// lower case, spaces to hyphens, most punctuation dropped.
func headingAnchor(title string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(title) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// TestCookbookAlgorithmTableMatchesJose checks the "Pick an algorithm for a
// key" table against algorithmFitsKey, the rule --alg enforces, so the table
// cannot promise a pairing jose refuses or omit one it accepts.
func TestCookbookAlgorithmTableMatchesJose(t *testing.T) {
	t.Parallel()

	var table string
	for _, section := range parseCookbook(t) {
		if section.title == "Pick an algorithm for a key" {
			table = section.body
		}
	}
	if table == "" {
		t.Fatal(`the cookbook has no "Pick an algorithm for a key" section`)
	}

	rows := map[string]string{}
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 2 || strings.HasPrefix(strings.TrimSpace(cells[0]), ":--") || strings.TrimSpace(cells[0]) == "Algorithm" {
			continue
		}
		for _, alg := range strings.Split(cells[0], ",") {
			rows[strings.TrimSpace(alg)] = strings.TrimSpace(cells[1])
		}
	}

	keys := []struct {
		keyType, curve string
		size           int
		inTable        func(cell string) bool
	}{
		{"RSA", "", 2048, func(c string) bool { return c == "RSA" }},
		{"EC", "P-256", 0, func(c string) bool { return c == "EC P-256" || strings.HasPrefix(c, "EC (any curve)") }},
		{"EC", "P-384", 0, func(c string) bool { return c == "EC P-384" || strings.HasPrefix(c, "EC (any curve)") }},
		{"EC", "P-521", 0, func(c string) bool { return c == "EC P-521" || strings.HasPrefix(c, "EC (any curve)") }},
		{"OKP", "Ed25519", 0, func(c string) bool { return c == "OKP Ed25519" }},
		{"OKP", "X25519", 0, func(c string) bool { return strings.HasSuffix(c, "OKP X25519") }},
		{"oct", "", 256, octCellAccepts(256)},
		{"oct", "", 384, octCellAccepts(384)},
		{"oct", "", 512, octCellAccepts(512)},
	}

	algs := append(append([]string{}, supportedSignatureAlgorithms()...), supportedKeyEncryptionAlgorithms()...)
	var missing []string
	for _, alg := range algs {
		cell, ok := rows[alg]
		if !ok {
			// Algorithms whose keys jose cannot generate are named in the
			// prose below the table instead.
			if !strings.Contains(table, alg) {
				missing = append(missing, alg)
			}
			continue
		}
		for _, k := range keys {
			if got, want := k.inTable(cell), algorithmFitsKey(alg, k.keyType, k.curve, k.size); got != want {
				t.Errorf("%s with %s %s %d: the table says %v (%q), jose says %v", alg, k.keyType, k.curve, k.size, got, cell, want)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("algorithms the cookbook does not mention: %s", strings.Join(missing, ", "))
	}
}

// octCellAccepts reads an oct cell of the algorithm table ("oct", "oct, 384
// bits or more", "oct, exactly 256 bits") for a key of size bits.
func octCellAccepts(size int) func(string) bool {
	return func(cell string) bool {
		rest, ok := strings.CutPrefix(cell, "oct")
		if !ok {
			return false
		}
		rest = strings.TrimPrefix(rest, ", ")
		switch {
		case rest == "":
			return true
		case strings.HasSuffix(rest, " bits or more"):
			bits, err := strconv.Atoi(strings.TrimSuffix(rest, " bits or more"))
			if err != nil {
				return false
			}
			return size >= bits
		case strings.HasPrefix(rest, "exactly ") && strings.HasSuffix(rest, " bits"):
			bits, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rest, "exactly "), " bits"))
			if err != nil {
				return false
			}
			return size == bits
		}
		return false
	}
}

// TestReferenceListsEveryFlag checks that the reference page names every
// command, and lists every flag in the "## <command>" section of the command
// that owns it, so a flag cannot ship undocumented or be documented under the
// wrong command.
func TestReferenceListsEveryFlag(t *testing.T) {
	t.Parallel()
	reference := readDoc(t, referencePath)

	sections := map[string]string{}
	var title string
	for _, line := range strings.Split(reference, "\n") {
		if heading, ok := strings.CutPrefix(line, "## "); ok {
			title = heading
			continue
		}
		sections[title] += line + "\n"
	}

	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Hidden || cmd.Name() == "help" {
			return
		}
		path := cmd.CommandPath()
		if !strings.Contains(reference, "`"+path) && !strings.Contains(reference, "## "+path) {
			t.Errorf("the reference page does not mention %q", path)
		}
		cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" {
				return
			}
			section, ok := sections[path]
			if !ok {
				t.Errorf("%s has flags but the reference page has no \"## %s\" section", path, path)
				return
			}
			if !strings.Contains(section, "| `--"+f.Name+"`") {
				t.Errorf("the %q section of the reference page does not list --%s in its flag table", path, f.Name)
			}
		})
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(newRootCmd())
}

// TestSiteShellBlocksAreRun checks the README and the website pages other than
// the cookbook the same way: each of their shell blocks must be run verbatim by
// e2e/atago/site.atago.yaml. Install commands are exempt, since they install
// software on the host, and so is the install page as a whole.
func TestSiteShellBlocksAreRun(t *testing.T) {
	t.Parallel()

	var spec cookbookSpec
	if err := yaml.Unmarshal([]byte(readDoc(t, "../e2e/atago/site.atago.yaml")), &spec); err != nil {
		t.Fatal(err)
	}
	run := map[string]bool{}
	for _, scenario := range spec.Scenarios {
		for _, step := range scenario.Steps {
			if step.Run != nil && step.Run.Shell {
				run[strings.TrimRight(step.Run.Command, "\n")] = true
			}
		}
	}

	for _, page := range []string{"../README.md", "../website/content/_index.md", referencePath} {
		blocks := fencedBlocks(readDoc(t, page), "shell")
		if len(blocks) == 0 {
			t.Errorf("%s has no shell block; drop it from this test or add one", page)
		}
		for _, block := range blocks {
			if strings.HasPrefix(block, "brew install ") || strings.HasPrefix(block, "GOEXPERIMENT=jsonv2 go install ") {
				// Installs software on the host; the install page's job.
				continue
			}
			if !run[block] {
				t.Errorf("%s: this shell block is not run verbatim by e2e/atago/site.atago.yaml:\n%s", page, block)
			}
		}
	}
}

// fencedBlocks returns the bodies of the fenced code blocks tagged info.
func fencedBlocks(markdown, info string) []string {
	var (
		blocks []string
		block  []string
		inside bool
	)
	for _, line := range strings.Split(markdown, "\n") {
		switch {
		case !inside && line == "```"+info:
			inside, block = true, nil
		case inside && line == "```":
			blocks = append(blocks, strings.Join(block, "\n"))
			inside = false
		case inside:
			block = append(block, line)
		}
	}
	return blocks
}
