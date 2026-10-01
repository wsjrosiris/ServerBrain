// Package policy decides whether a requested action may run, needs human
// approval, or is blocked. Rules are evaluated top to bottom; the first
// matching rule wins. If no rule matches, the request is blocked.
//
// Actor types make the three AI operating modes expressible as policy:
//   - read-only:  ai may only run read_only actions, everything else blocked
//   - assisted:   ai actions require approval
//   - autonomous: selected low-risk ai actions are allowed directly
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/wsjrosiris/serverbrain/internal/actions"
)

type Effect string

const (
	Allow   Effect = "allow"
	Approve Effect = "approve" // requires approval by an admin
	Block   Effect = "block"
)

// Actor types.
const (
	ActorHuman = "human"
	ActorAI    = "ai"
)

// Roles, in increasing order of privilege.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

type Rule struct {
	Name       string         `json:"name"`
	Actions    []string       `json:"actions,omitempty"`     // glob patterns, e.g. "service.*"
	Risks      []actions.Risk `json:"risks,omitempty"`       // low, medium, high, critical
	ReadOnly   *bool          `json:"read_only,omitempty"`   // match only (non-)read-only actions
	Servers    []string       `json:"servers,omitempty"`     // hostname glob patterns
	Tags       []string       `json:"tags,omitempty"`        // server must carry one of these tags
	ActorTypes []string       `json:"actor_types,omitempty"` // human, ai
	Roles      []string       `json:"roles,omitempty"`       // viewer, operator, admin
	Effect     Effect         `json:"effect"`
}

type Policy struct {
	// AllowSelfApproval lets an admin approve a request they made themselves.
	// Disable it to enforce the four-eyes principle.
	AllowSelfApproval bool   `json:"allow_self_approval"`
	Rules             []Rule `json:"rules"`
}

// Request describes who wants to do what, where.
type Request struct {
	Action    *actions.Def
	Hostname  string
	Tags      []string
	ActorType string
	Role      string
}

type Decision struct {
	Effect Effect `json:"effect"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

func boolPtr(b bool) *bool { return &b }

// Default returns the built-in policy used when no policy file is given.
func Default() *Policy {
	return &Policy{
		AllowSelfApproval: true,
		Rules: []Rule{
			{Name: "viewers-read-only", Roles: []string{RoleViewer}, ReadOnly: boolPtr(false), Effect: Block},
			{Name: "read-only-actions", ReadOnly: boolPtr(true), Effect: Allow},
			{Name: "shell-admin-only", Actions: []string{"shell.run"}, ActorTypes: []string{ActorHuman}, Roles: []string{RoleAdmin}, Effect: Allow},
			{Name: "shell-blocked", Actions: []string{"shell.run"}, Effect: Block},
			{Name: "reboot-needs-approval", Actions: []string{"system.reboot"}, Effect: Approve},
			{Name: "ai-autonomous-remediation", ActorTypes: []string{ActorAI},
				Actions: []string{"service.restart", "service.start", "iis.apppool.restart", "temp.cleanup"}, Effect: Allow},
			{Name: "ai-assisted", ActorTypes: []string{ActorAI}, Effect: Approve},
			{Name: "humans-low-medium", ActorTypes: []string{ActorHuman}, Risks: []actions.Risk{actions.RiskLow, actions.RiskMedium}, Effect: Allow},
			{Name: "humans-high-needs-approval", ActorTypes: []string{ActorHuman}, Risks: []actions.Risk{actions.RiskHigh}, Effect: Approve},
		},
	}
}

// Load reads a policy from a JSON file.
func Load(file string) (*Policy, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", file, err)
	}
	for i, r := range p.Rules {
		switch r.Effect {
		case Allow, Approve, Block:
		default:
			return nil, fmt.Errorf("policy rule %d (%s): invalid effect %q", i, r.Name, r.Effect)
		}
	}
	return &p, nil
}

// Evaluate returns the decision for a request.
func (p *Policy) Evaluate(req Request) Decision {
	for _, r := range p.Rules {
		if r.matches(req) {
			return Decision{Effect: r.Effect, Rule: r.Name, Reason: fmt.Sprintf("matched rule %q", r.Name)}
		}
	}
	return Decision{Effect: Block, Rule: "default-deny", Reason: "no policy rule matched"}
}

func (r *Rule) matches(req Request) bool {
	a := req.Action
	if len(r.Actions) > 0 && !anyGlob(r.Actions, a.Name) {
		return false
	}
	if len(r.Risks) > 0 {
		ok := false
		for _, risk := range r.Risks {
			ok = ok || risk == a.Risk
		}
		if !ok {
			return false
		}
	}
	if r.ReadOnly != nil && *r.ReadOnly != a.ReadOnly {
		return false
	}
	if len(r.Servers) > 0 && !anyGlob(r.Servers, strings.ToLower(req.Hostname)) {
		return false
	}
	if len(r.Tags) > 0 && !intersects(r.Tags, req.Tags) {
		return false
	}
	if len(r.ActorTypes) > 0 && !contains(r.ActorTypes, req.ActorType) {
		return false
	}
	if len(r.Roles) > 0 && !contains(r.Roles, req.Role) {
		return false
	}
	return true
}

func anyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(strings.ToLower(p), s); ok {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}
