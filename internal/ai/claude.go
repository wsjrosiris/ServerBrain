package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

// ClaudeConfig configures the Claude provider.
type ClaudeConfig struct {
	Model     string // default claude-opus-5-5
	Effort    string // low, medium, high, xhigh, max (default high)
	MaxTokens int64  // per response, default 16000
	APIKey    string // optional; otherwise the SDK's credential chain is used
	BaseURL   string // optional, for tests or a gateway
}

// Claude talks to Anthropic's Messages API through the official Go SDK.
type Claude struct {
	client anthropic.Client
	cfg    ClaudeConfig
}

func NewClaude(cfg ClaudeConfig) *Claude {
	if cfg.Model == "" {
		cfg.Model = "claude-opus-5-5"
	}
	if cfg.Effort == "" {
		cfg.Effort = "high"
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 16000
	}
	var opts []option.RequestOption
	if cfg.APIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.APIKey))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	return &Claude{client: anthropic.NewClient(opts...), cfg: cfg}
}

func (c *Claude) Name() string { return c.cfg.Model }

func (c *Claude) NewConversation(system string, tools []Tool) Conversation {
	defs := make([]anthropic.BetaToolUnionParam, 0, len(tools))
	for i, t := range tools {
		tp := &anthropic.BetaToolParam{
			Name:        t.Name,
			Description: param.NewOpt(t.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{Properties: t.Properties, Required: t.Required},
		}
		if i == len(tools)-1 {
			// Cache breakpoint after the (stable) tool list.
			tp.CacheControl = anthropic.NewBetaCacheControlEphemeralParam()
		}
		defs = append(defs, anthropic.BetaToolUnionParam{OfTool: tp})
	}
	return &claudeConversation{c: c, system: system, tools: defs}
}

type claudeConversation struct {
	c      *Claude
	system string
	tools  []anthropic.BetaToolUnionParam

	mu       sync.Mutex
	messages []anthropic.BetaMessageParam
}

func (cv *claudeConversation) Ask(ctx context.Context, text string) (*Reply, error) {
	return cv.send(ctx, anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(text)))
}

func (cv *claudeConversation) Answer(ctx context.Context, results []ToolResult) (*Reply, error) {
	blocks := make([]anthropic.BetaContentBlockParamUnion, 0, len(results))
	for _, r := range results {
		blocks = append(blocks, anthropic.NewBetaToolResultBlock(r.CallID, r.Content, r.IsError))
	}
	// All results of one assistant turn go back in a single user message.
	return cv.send(ctx, anthropic.NewBetaUserMessage(blocks...))
}

func (cv *claudeConversation) send(ctx context.Context, msg anthropic.BetaMessageParam) (*Reply, error) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	messages := append(cv.messages, msg)
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(cv.c.cfg.Model),
		MaxTokens: cv.c.cfg.MaxTokens,
		System: []anthropic.BetaTextBlockParam{{
			Text:         cv.system,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages:     messages,
		Tools:        cv.tools,
		Thinking:     anthropic.BetaThinkingConfigParamUnion{OfAdaptive: &anthropic.BetaThinkingConfigAdaptiveParam{}},
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffort(cv.c.cfg.Effort)},
		// If a safety classifier declines, Anthropic re-serves the request
		// with a suitable fallback model inside the same call.
		Fallbacks: anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()},
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	}
	resp, err := cv.c.client.Beta.Messages.New(ctx, params)
	if err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			return nil, fmt.Errorf("claude API %d: %s", apiErr.StatusCode, strings.TrimSpace(apiErr.Error()))
		}
		return nil, err
	}
	// Append-only history: the reply goes back verbatim, thinking included.
	cv.messages = append(messages, resp.ToParam())

	out := &Reply{Stop: string(resp.StopReason), InputTokens: resp.Usage.InputTokens, OutputTokens: resp.Usage.OutputTokens}
	var text []string
	for _, block := range resp.Content {
		switch b := block.AsAny().(type) {
		case anthropic.BetaTextBlock:
			text = append(text, b.Text)
		case anthropic.BetaToolUseBlock:
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Input: []byte(b.JSON.Input.Raw())})
		}
	}
	out.Text = strings.Join(text, "\n\n")
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		out.Text = strings.TrimSpace(out.Text + "\n\n_(Die Anfrage wurde vom Modell abgelehnt.)_")
	}
	return out, nil
}
