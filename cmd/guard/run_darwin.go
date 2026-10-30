//go:build darwin

package main

import (
	"os/exec"

	"guard/internal/policy"
	"guard/internal/sandbox"
)

func buildCommand(_ *policy.Resolved, profPath string, env []string, argv []string) (*exec.Cmd, func(), error) {
	return sandbox.Command(profPath, env, argv), func() {}, nil
}
