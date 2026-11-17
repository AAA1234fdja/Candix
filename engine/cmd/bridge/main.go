package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/AAA1234fdja/candix/engine/intercept"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: bridge <score-risk|normalize-target|check-target> [json]\n")
		os.Exit(2)
	}
	cmd := os.Args[1]
	var input []byte
	if len(os.Args) > 2 {
		input = []byte(os.Args[2])
	} else {
		// read stdin
		b, _ := os.ReadFile("/dev/stdin")
		input = b
	}
	switch cmd {
	case "score-risk":
		var req struct {
			Tool  string          `json:"tool"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(input, &req); err != nil {
			fmt.Fprintf(os.Stderr, "bad json: %v\n", err)
			os.Exit(1)
		}
		report := intercept.ScoreRisk(req.Tool, req.Input)
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.Encode(report)
	case "normalize-target":
		var req struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal(input, &req); err != nil {
			// treat raw as plain string
			req.Raw = string(input)
			if req.Raw == "" {
				req.Raw = string(input)
			}
		}
		t, ok := intercept.NormalizeTarget(req.Raw)
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"ok":     ok,
			"target": t,
		})
	case "version":
		json.NewEncoder(os.Stdout).Encode(map[string]string{"version": "bridge-1.0", "module": "github.com/AAA1234fdja/candix/engine"})
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}
