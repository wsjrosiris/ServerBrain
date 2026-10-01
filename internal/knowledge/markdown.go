package knowledge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Managed Markdown files. ServerBrain owns two things in a note:
//   - its frontmatter properties (other properties are preserved), and
//   - the region between the begin/end markers.
// Everything else - your own notes, headings, links - is never touched.
// The markers are Obsidian comments, invisible in reading view.

const (
	markerBegin = "%% serverbrain:begin – automatisch gepflegt, Änderungen in diesem Bereich werden überschrieben %%"
	markerEnd   = "%% serverbrain:end %%"
	markerKey   = "%% serverbrain:begin"
)

// Prop is one frontmatter property. Value is a string, int, float64 or
// []string.
type Prop struct {
	Key   string
	Value any
}

func yamlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ").Replace(s) + `"`
}

func renderProps(props []Prop) []string {
	var lines []string
	for _, p := range props {
		switch v := p.Value.(type) {
		case []string:
			if len(v) == 0 {
				lines = append(lines, p.Key+": []")
				continue
			}
			lines = append(lines, p.Key+":")
			for _, x := range v {
				lines = append(lines, "  - "+yamlQuote(x))
			}
		case string:
			lines = append(lines, p.Key+": "+yamlQuote(v))
		default:
			lines = append(lines, fmt.Sprintf("%s: %v", p.Key, v))
		}
	}
	return lines
}

// splitFrontmatter returns the frontmatter lines (without the --- fences)
// and the body. ok is false if the document has no frontmatter.
func splitFrontmatter(doc string) (fm []string, body string, ok bool) {
	doc = strings.ReplaceAll(doc, "\r\n", "\n")
	if !strings.HasPrefix(doc, "---\n") {
		return nil, doc, false
	}
	rest := doc[4:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return nil, doc, false
	}
	after := rest[end+4:]
	after = strings.TrimPrefix(after, "\n")
	return strings.Split(rest[:end], "\n"), after, true
}

// foreignProps returns frontmatter entries (key line plus continuation
// lines) whose key ServerBrain does not own.
func foreignProps(fm []string, owned map[string]bool) []string {
	var out []string
	keep := false
	for _, line := range fm {
		if line != "" && line[0] != ' ' && line[0] != '\t' && line[0] != '-' && line[0] != '#' {
			key, _, _ := strings.Cut(line, ":")
			keep = !owned[strings.TrimSpace(key)]
		}
		if keep {
			out = append(out, line)
		}
	}
	return out
}

// Merge produces the new document from the existing one (may be empty).
// newDoc is used for the body when the note does not exist yet; it must
// contain the managed block.
func Merge(existing string, props []Prop, block string, newBody string) string {
	owned := map[string]bool{}
	for _, p := range props {
		owned[p.Key] = true
	}
	fm, body, hasFM := splitFrontmatter(existing)
	lines := renderProps(props)
	if hasFM {
		lines = append(lines, foreignProps(fm, owned)...)
	}
	managed := markerBegin + "\n" + strings.TrimRight(block, "\n") + "\n" + markerEnd

	var newBodyText string
	switch {
	case strings.TrimSpace(existing) == "":
		newBodyText = strings.Replace(newBody, "{{block}}", managed, 1)
	default:
		b := strings.Index(body, markerKey)
		e := strings.Index(body, markerEnd)
		if b >= 0 && e > b {
			newBodyText = body[:b] + managed + body[e+len(markerEnd):]
		} else {
			// A note with this name exists but has no managed block yet:
			// insert it after the first heading (or at the top).
			if i := strings.Index(body, "\n"); strings.HasPrefix(body, "# ") && i > 0 {
				newBodyText = body[:i+1] + "\n" + managed + "\n" + body[i+1:]
			} else {
				newBodyText = managed + "\n\n" + body
			}
		}
	}
	return "---\n" + strings.Join(lines, "\n") + "\n---\n" + newBodyText
}

// UserContent returns what a person wrote in a note: the body outside the
// managed block, without the title line and template placeholders.
func UserContent(doc string, placeholders ...string) string {
	_, body, _ := splitFrontmatter(doc)
	if b, e := strings.Index(body, markerKey), strings.Index(body, markerEnd); b >= 0 && e > b {
		body = body[:b] + body[e+len(markerEnd):]
	}
	var out []string
	for i, line := range strings.Split(body, "\n") {
		if i < 2 && strings.HasPrefix(line, "# ") {
			continue
		}
		skip := false
		for _, p := range placeholders {
			if strings.TrimSpace(line) == p {
				skip = true
			}
		}
		if !skip {
			out = append(out, line)
		}
	}
	text := strings.TrimSpace(strings.Join(out, "\n"))
	// A lone, empty "## Notizen" heading carries no information.
	if text == "## Notizen" {
		return ""
	}
	return text
}

// writeIfChanged writes content atomically when it differs from what is on
// disk, so sync tools (Obsidian Sync, Git, Syncthing) see no churn.
func writeIfChanged(path, content string) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".sbtmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}

// NoteName turns a hostname into a safe Obsidian note name.
func NoteName(host string) string {
	r := strings.NewReplacer(`\`, "-", "/", "-", ":", "-", "*", "-", "?", "-", `"`, "-", "<", "-", ">", "-", "|", "-", "#", "-", "^", "-", "[", "(", "]", ")")
	n := strings.TrimSpace(r.Replace(host))
	if n == "" || n == "." || n == ".." {
		return "unbenannt"
	}
	return n
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "[[", `\[\[`).Replace(s)
}

// indent prefixes every line with a tab so multi-line details nest under
// a list item in Obsidian.
func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "\t" + l
	}
	return strings.Join(lines, "\n")
}
