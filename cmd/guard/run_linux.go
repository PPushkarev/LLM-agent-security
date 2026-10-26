//go:build linux

package main

import (
	"os/exec"

	"guard/internal/policy"
	"guard/internal/sandbox"
)

func buildCommand(r *policy.Resolved, _ string, env []string, argv []string) *exec.Cmd {
	return sandbox.CommandFor(r, env, argv)
}
