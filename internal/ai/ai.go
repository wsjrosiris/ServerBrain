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

// Provider creates conversations.
type Provider interface {
	NewConversation(system string, tools []Tool) Conversation
	Name() string
}
