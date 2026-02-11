package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	apiKey    string
	timeout   string
	language  string
	memoryMB  int64
)

func main() {
	root := &cobra.Command{
		Use:   "sandbox-cli",
		Short: "CLI client for safe-agent-sandbox",
	}

	root.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:8080", "Server URL")
	root.PersistentFlags().StringVar(&apiKey, "api-key", os.Getenv("SANDBOX_API_KEY"), "API key")

	// Execute command
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

	// Execute from file
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

	// Health check
	root.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Check server health",
		RunE:  runHealth,
	})

	// List executions
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
		// Read from stdin
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		code = string(data)
	}

	return executeCode(code, language)
}

func runExecFile(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Auto-detect language from extension
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

	return executeCode(string(data), language)
}

func executeCode(code, lang string) error {
	payload := map[string]any{
		"code":     code,
		"language": lang,
		"timeout":  timeout,
		"limits": map[string]any{
			"memory_mb": memoryMB,
			"cpu_shares": 512,
			"pids_limit": 50,
			"disk_mb":    100,
		},
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

	client := &http.Client{Timeout: 70 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Pretty print
	formatted, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(formatted))

	// Exit with the sandbox exit code
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
	json.NewDecoder(resp.Body).Decode(&result)
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
	json.NewDecoder(resp.Body).Decode(&result)
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
