package policy

import (
	"testing"

	"github.com/wsjrosiris/serverbrain/internal/actions"
)

func TestDefaultPolicy(t *testing.T) {
	p := Default()
	get := func(n string) *actions.Def { d, _ := actions.Get(n); return d }
	cases := []struct {
		action, actor, role string
		want                Effect
	}{
		{"disk.large_files", ActorAI, RoleOperator, Allow},     // read-only
		{"disk.large_files", ActorHuman, RoleViewer, Allow},    // viewers may read
		{"service.restart", ActorHuman, RoleViewer, Block},     // viewers may not change
		{"service.restart", ActorAI, RoleOperator, Allow},      // autonomous remediation
		{"files.archive_old", ActorAI, RoleOperator, Approve},  // assisted
		{"files.archive_old", ActorHuman, RoleOperator, Allow}, // medium risk human
		{"system.reboot", ActorHuman, RoleAdmin, Approve},      // always approval
		{"system.reboot", ActorAI, RoleOperator, Approve},
		{"shell.run", ActorHuman, RoleAdmin, Allow},
		{"shell.run", ActorHuman, RoleOperator, Block},
		{"shell.run", ActorAI, RoleOperator, Block},
	}
	for _, c := range cases {
		got := p.Evaluate(Request{Action: get(c.action), Hostname: "WEB-03", ActorType: c.actor, Role: c.role})
		if got.Effect != c.want {
			t.Errorf("%s by %s/%s: got %s (%s), want %s", c.action, c.actor, c.role, got.Effect, got.Rule, c.want)
		}
	}
}

func TestServerAndTagMatching(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Name: "dc-protected", Tags: []string{"domain-controller"}, ReadOnly: boolPtr(false), Effect: Block},
		{Name: "web", Servers: []string{"web-*"}, Effect: Allow},
	}}
	d, _ := actions.Get("service.restart")
	if e := p.Evaluate(Request{Action: d, Hostname: "WEB-01"}).Effect; e != Allow {
		t.Errorf("web glob: got %s", e)
	}
	if e := p.Evaluate(Request{Action: d, Hostname: "WEB-01", Tags: []string{"domain-controller"}}).Effect; e != Block {
		t.Errorf("tag block: got %s", e)
	}
	if e := p.Evaluate(Request{Action: d, Hostname: "SQL-01"}).Effect; e != Block {
		t.Errorf("default deny: got %s", e)
	}
}

func TestExamplePolicyLoads(t *testing.T) {
	p, err := Load("../../deploy/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := actions.Get("service.restart")
	if e := p.Evaluate(Request{Action: d, Hostname: "WEB-03", Tags: []string{"web"}, ActorType: ActorAI, Role: RoleOperator}).Effect; e != Allow {
		t.Errorf("ai restart on web: got %s", e)
	}
	if e := p.Evaluate(Request{Action: d, Hostname: "DC01", Tags: []string{"domain-controller"}, ActorType: ActorAI, Role: RoleOperator}).Effect; e != Block {
		t.Errorf("ai restart on DC: got %s", e)
	}
}
