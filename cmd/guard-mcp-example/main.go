// guard-mcp-example is a local MCP server for testing guard without cloud services.
package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "guard-example", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", Description: "Echo the supplied text", InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string","maxLength":2000}},"required":["text"],"additionalProperties":false}`)}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(r.Params.Arguments, &a); err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: a.Text}}}, nil
	})
	if err := server.Run(context.Background(), &mcp.StdioTransport{MaxLineLength: 2 << 20}); err != nil {
		os.Exit(1)
	}
}
