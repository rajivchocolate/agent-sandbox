package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	apiKey    string
	timeout   string
	language  string
	memoryMB  int64
	workDir   string
)

func main() {
	root := &cobra.Command{
		Use:   "sandbox-cli",
		Short: "CLI client for safe-agent-sandbox",
	}

	root.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:8080", "Server URL")
	root.PersistentFlags().StringVar(&apiKey, "api-key", os.Getenv("SANDBOX_API_KEY"), "API key")

	execCmd := &cobra.Command{
		Use:   "exec [code]",
		Short: "Execute code in a sandbox",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runExec,
	}
	execCmd.Flags().StringVar(&timeout, "timeout", "10s", "Execution timeout")
	execCmd.Flags().StringVarP(&language, "language", "l", "python", "Language (python, node, bash)")
	execCmd.Flags().Int64Var(&memoryMB, "memory", 256, "Memory limit in MB")
	root.AddCommand(execCmd)

	execFileCmd := &cobra.Command{
		Use:   "exec-file [file]",
		Short: "Execute code from a file",
		Args:  cobra.ExactArgs(1),
		RunE:  runExecFile,
	}
	execFileCmd.Flags().StringVar(&timeout, "timeout", "10s", "Execution timeout")
	execFileCmd.Flags().StringVarP(&language, "language", "l", "", "Language (auto-detected from extension)")
	execFileCmd.Flags().Int64Var(&memoryMB, "memory", 256, "Memory limit in MB")
	root.AddCommand(execFileCmd)

	claudeCmd := &cobra.Command{
		Use:   "claude [prompt]",
		Short: "Run Claude Code in a sandboxed container",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runClaude,
	}
	claudeCmd.Flags().StringVar(&workDir, "dir", "", "Project directory to mount (default: current directory)")
	claudeCmd.Flags().StringVar(&timeout, "timeout", "5m", "Execution timeout")
	claudeCmd.Flags().Int64Var(&memoryMB, "memory", 1024, "Memory limit in MB")
	root.AddCommand(claudeCmd)

	root.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Check server health",
		RunE:  runHealth,
	})

	root.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List recent executions",
		RunE:  runList,
	})

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runExec(cmd *cobra.Command, args []string) error {
	var code string

	if len(args) > 0 {
		code = args[0]
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		code = string(data)
	}

	return executeCode(code, language, "")
}

func runClaude(_ *cobra.Command, args []string) error {
	var prompt string

	if len(args) > 0 {
		prompt = args[0]
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		prompt = string(data)
	}

	if prompt == "" {
		return fmt.Errorf("prompt is required")
	}

	dir := workDir
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
		dir = cwd
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving directory: %w", err)
	}

	return executeCode(prompt, "claude", absDir)
}

func runExecFile(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if language == "" {
		switch ext := fileExtension(args[0]); ext {
		case ".py":
			language = "python"
		case ".js":
			language = "node"
		case ".sh":
			language = "bash"
		default:
			return fmt.Errorf("cannot detect language for extension %q, use --language flag", ext)
		}
	}

	return executeCode(string(data), language, "")
}

func executeCode(code, lang, projectDir string) error {
	payload := map[string]any{
		"code":     code,
		"language": lang,
		"timeout":  timeout,
		"limits": map[string]any{
			"memory_mb":  memoryMB,
			"cpu_shares": 512,
			"pids_limit": 50,
			"disk_mb":    100,
		},
	}

	if lang == "claude" {
		payload["limits"] = map[string]any{
			"memory_mb":  memoryMB,
			"cpu_shares": 2048,
			"pids_limit": 200,
			"disk_mb":    500,
		}
		if projectDir != "" {
			payload["work_dir"] = projectDir
		}
	}

	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", serverURL+"/execute", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	httpTimeout := 70 * time.Second
	if lang == "claude" {
		httpTimeout = 6 * time.Minute
	}
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	formatted, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(formatted))

	if exitCode, ok := result["exit_code"].(float64); ok && exitCode != 0 {
		os.Exit(int(exitCode))
	}

	return nil
}

func runHealth(_ *cobra.Command, _ []string) error {
	resp, err := http.Get(serverURL + "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	formatted, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(formatted))
	return nil
}

func runList(_ *cobra.Command, _ []string) error {
	req, _ := http.NewRequest("GET", serverURL+"/executions", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	formatted, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(formatted))
	return nil
}

func fileExtension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
	}
	return ""
}
