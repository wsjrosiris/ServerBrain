package actions

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	d, _ := Get("eventlog.query")
	p, err := d.Validate(map[string]any{"hours": float64(12)})
	if err != nil {
		t.Fatal(err)
	}
	if p["hours"] != "12" || p["log"] != "System" || p["max"] != "50" {
		t.Fatalf("defaults not applied: %v", p)
	}

	svc, _ := Get("service.restart")
	cases := []map[string]any{
		{},                                   // missing required
		{"name": "W3SVC'; Remove-Item C:\\"}, // injection attempt rejected by pattern
		{"name": "W3SVC", "extra": "x"},      // unknown parameter
	}
	for _, c := range cases {
		if _, err := svc.Validate(c); err == nil {
			t.Errorf("expected error for %v", c)
		}
	}
	if _, err := d.Validate(map[string]any{"hours": float64(100000)}); err == nil {
		t.Error("expected range error")
	}
	if _, err := d.Validate(map[string]any{"hours": 1.5}); err == nil {
		t.Error("expected integer error")
	}
}

func TestPreviewUsesEnvironment(t *testing.T) {
	d, _ := Get("service.restart")
	p, err := d.Validate(map[string]any{"name": "W3SVC"})
	if err != nil {
		t.Fatal(err)
	}
	prev := d.Preview("windows", p)
	if !strings.Contains(prev, `SB_ARG_NAME = "W3SVC"`) || !strings.Contains(prev, "$env:SB_ARG_NAME") {
		t.Fatalf("unexpected preview:\n%s", prev)
	}
}

func TestCatalogConsistency(t *testing.T) {
	for _, d := range All() {
		if d.Kind == KindScript && len(d.Scripts) == 0 {
			t.Errorf("%s: script action without scripts", d.Name)
		}
		if d.Kind == KindNative && d.Native == "" {
			t.Errorf("%s: native action without description", d.Name)
		}
		for _, p := range d.Params {
			if p.Default != "" {
				if _, err := d.Validate(map[string]any{p.Name: p.Default}); err != nil && !strings.Contains(err.Error(), "required") {
					t.Errorf("%s: default for %s invalid: %v", d.Name, p.Name, err)
				}
			}
		}
	}
}
