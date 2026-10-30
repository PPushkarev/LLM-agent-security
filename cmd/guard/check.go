package main

import (
	"fmt"
	"strings"

	"guard/internal/policy"
	"guard/internal/sandbox"
)

func checkCmd(args []string) {
	path, _, argv := parseArgs(args)
	if path == "" || len(argv) > 0 {
		die("usage: guard check --policy FILE")
	}
	r, err := policy.Load(path)
	if err != nil {
		die("%v", err)
	}
	if _, err := sandbox.Profile(r); err != nil {
		die("%v", err)
	}
	fmt.Printf("Policy OK\nBackend: %s\nWorkspace: %s\nRoutes: %d\nFilter: enabled=%t mode=%s\n", sandbox.Backend(), r.Workspace, len(r.KeyInject), r.PromptFilter.Enabled, r.PromptFilter.Mode)
	for _, rt := range r.KeyInject {
		fmt.Printf("  %s -> %s methods=%v paths=%v models=%v JSON rules=%d\n", rt.Prefix, rt.Upstream, rt.Methods, rt.AllowPaths, rt.JSON.AllowModels, len(rt.JSON.Rules))
	}
	fmt.Printf("Model response gate: enabled=%t rules=%d JSON rules=%d schema=%t\n", r.PromptFilter.ScanResponses, len(r.PromptFilter.ResponseRules)+len(r.PromptFilter.ResponseBlock), len(r.PromptFilter.ResponseJSON.Rules), len(r.PromptFilter.ResponseSchema) > 0 && strings.TrimSpace(string(r.PromptFilter.ResponseSchema)) != "null")
	if r.PromptInjection.Enabled {
		cfg := r.PromptInjection.Defaults()
		fmt.Printf("Prompt injection classifier: ON model=%s action=%s threshold=%.3f sources=%v\n", cfg.Model, cfg.Action, cfg.Threshold, cfg.Sources)
	} else {
		fmt.Println("Prompt injection classifier: OFF (regex/JSON checks only)")
	}
	fmt.Printf("Guardrails: strict=%t max_session_seconds=%d max_output_bytes=%d session_audit=%t\n", r.Guardrails.Strict, r.Guardrails.MaxSessionSeconds, r.Guardrails.MaxOutputBytes, r.Guardrails.AuditLog != "")
	fmt.Printf("Managed MCP servers: %d\n", len(r.MCP.Servers))
	fmt.Println("Credentials and API availability are checked when starting a session.")
}
