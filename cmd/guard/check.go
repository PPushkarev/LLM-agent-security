package main

import (
	"fmt"

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
	fmt.Printf("Managed MCP servers: %d\n", len(r.MCP.Servers))
	fmt.Println("Credentials and API availability are checked when starting a session.")
}
