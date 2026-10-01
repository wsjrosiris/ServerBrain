// Package ai connects ServerBrain to a large language model. The rest of
// the code depends only on the small Provider/Conversation interfaces, so
// tests can script the model and the vendor SDK stays in one file.
package ai

import (
	"context"
	"encoding/json"
)

// Tool is a function the model may call.
type Tool struct {
	Name        string
	Description string
	// Properties is the JSON Schema "properties" object; Required lists
	// mandatory property names.
	Properties map[string]any
	Required   []string
}

// ToolCall is a model request to run a tool.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ToolResult answers a ToolCall.
type ToolResult struct {
	CallID  string
	Content string
	IsError bool
}

// Reply is one model turn.
type Reply struct {
	Text      string     // visible text of this turn
	ToolCalls []ToolCall // tools the model wants to run
	// Stop is "end_turn", "tool_use", "max_tokens", "refusal", ...
	Stop         string
	InputTokens  int64
	OutputTokens int64
}

// Conversation is an append-only dialogue with the model: replies are kept
// verbatim (including reasoning blocks) so the model keeps its train of
// thought across tool calls.
type Conversation interface {
	// Ask adds a user message and returns the model's reply.
	Ask(ctx context.Context, text string) (*Reply, error)
	// Answer returns tool results and returns the model's next reply.
	Answer(ctx context.Context, results []ToolResult) (*Reply, error)
}

// Provider is a configured LLM backend. It is either a ConversationProvider
// (ServerBrain runs the tool loop, e.g. the Claude API) or an AgentRunner
// (the backend runs the loop itself and calls ServerBrain's tools via MCP,
// e.g. Claude Code with a Claude subscription).
type Provider interface {
	Name() string
}

// ConversationProvider creates conversations driven by ServerBrain.
type ConversationProvider interface {
	Provider
	NewConversation(system string, tools []Tool) Conversation
}

// AgentRunner runs a complete agent turn on its own. The tools are served
// to it by ServerBrain's MCP endpoint at MCPURL, authorized by MCPToken.
type AgentRunner interface {
	Provider
	RunAgent(ctx context.Context, req AgentRequest) (*AgentResult, error)
}

type AgentRequest struct {
	System    string
	Prompt    string
	SessionID string // continue this agent session (follow-up question)
	MCPURL    string
	MCPToken  string
	// OnText receives text the model writes between tool calls.
	OnText func(text string)
}

type AgentResult struct {
	Text      string
	SessionID string
	Turns     int
	CostUSD   float64
}
