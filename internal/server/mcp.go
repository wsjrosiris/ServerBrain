package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/ai"
	"github.com/wsjrosiris/serverbrain/internal/store"
)

// MCP endpoint for agent backends that run the tool loop themselves
// (Claude Code with a Claude subscription). It serves exactly the tools of
// one assistant run, authorized by a per-run token, and executes them with
// the same code path as the API backend (runTool): same actor, same policy,
// same transcript steps, same audit.
//
// It listens on a separate loopback-only HTTP port, so it is never exposed
// with the operator API and needs no TLS.

type mcpHub struct {
	mu     sync.Mutex
	url    string
	tokens map[string]*Run
}

// ensureMCP starts the loopback MCP listener once and returns its URL.
func (s *Server) ensureMCP() (string, error) {
	h := s.mcp
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.url != "" {
		return h.url, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", s.handleMCP)
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed) // no server-initiated stream
	})
	mux.HandleFunc("DELETE /mcp", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	go (&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
	h.url = "http://" + ln.Addr().String() + "/mcp"
	s.log.Info("MCP endpoint for Claude Code started", "url", h.url)
	return h.url, nil
}

// MCPURL returns the loopback MCP endpoint (starting it if needed).
func (s *Server) MCPURL() (string, error) { return s.ensureMCP() }

func (s *Server) mcpRegister(run *Run) string {
	tok := store.NewToken("sbm_")
	s.mcp.mu.Lock()
	s.mcp.tokens[tok] = run
	s.mcp.mu.Unlock()
	return tok
}

func (s *Server) mcpRevoke(tok string) {
	s.mcp.mu.Lock()
	delete(s.mcp.tokens, tok)
	s.mcp.mu.Unlock()
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

var mcpProtocolVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true, "2025-11-25": true}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	s.mcp.mu.Lock()
	run := s.mcp.tokens[bearer(r)]
	s.mcp.mu.Unlock()
	if run == nil {
		writeErr(w, http.StatusUnauthorized, "unknown or expired MCP token")
		return
	}
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&raw); err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		return
	}
	// Batches are allowed by older protocol versions.
	if len(raw) > 0 && raw[0] == '[' {
		var reqs []rpcRequest
		if err := json.Unmarshal(raw, &reqs); err != nil {
			writeJSON(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			return
		}
		var out []rpcResponse
		for _, req := range reqs {
			if resp := s.mcpDispatch(r.Context(), run, req); resp != nil {
				out = append(out, *resp)
			}
		}
		if len(out) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32600, "invalid request"}})
		return
	}
	resp := s.mcpDispatch(r.Context(), run, req)
	if resp == nil { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) mcpDispatch(ctx context.Context, run *Run, req rpcRequest) *rpcResponse {
	if len(req.ID) == 0 {
		return nil // notifications (e.g. notifications/initialized) need no answer
	}
	resp := &rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := "2025-06-18"
		if mcpProtocolVersions[p.ProtocolVersion] {
			version = p.ProtocolVersion
		}
		resp.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "serverbrain", "version": "1.0"},
			"instructions":    "ServerBrain-Tools: Wissen, Tagebuch, Ereignisse und Aktionen auf verwalteten Windows-Servern. Aktionen laufen durch die Policy.",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		var tools []map[string]any
		for _, t := range s.aiTools(run) {
			schema := map[string]any{"type": "object", "properties": t.Properties}
			if t.Properties == nil {
				schema["properties"] = map[string]any{}
			}
			if len(t.Required) > 0 {
				schema["required"] = t.Required
			}
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": schema})
		}
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			resp.Error = &rpcError{-32602, "invalid params"}
			return resp
		}
		if _, ok := s.toolByName(run, p.Name); !ok {
			resp.Error = &rpcError{-32602, fmt.Sprintf("unknown tool %q", p.Name)}
			return resp
		}
		res := s.runTool(ctx, run, ai.ToolCall{ID: store.NewID(), Name: p.Name, Input: p.Arguments})
		resp.Result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": res.Content}},
			"isError": res.IsError,
		}
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	return resp
}
