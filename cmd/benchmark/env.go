package main

import (
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
)

type environment struct {
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	NumCPU    int    `json:"num_cpu"`
	CPUModel  string `json:"cpu_model,omitempty"`
	CometBFT  string `json:"cometbft_version,omitempty"`
}

// captureEnvironment records what the numbers were measured on; benchmark
// results are meaningless without it.
func captureEnvironment() environment {
	env := environment{
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
	}

	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			env.CPUModel = strings.TrimSpace(string(out))
		}
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/cometbft/cometbft" {
				env.CometBFT = dep.Version
			}
		}
	}
	return env
}
