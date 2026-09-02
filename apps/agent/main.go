package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

type SecretResponse struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Path           string `json:"path"`
	CurrentVersion int    `json:"current_version"`
}

type RevealResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: aegis-agent run --project <id> --environment <id> --api-url <url> -- <command>")
		os.Exit(1)
	}

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	projectID := runCmd.String("project", "", "Project ID or Slug")
	envID := runCmd.String("environment", "", "Environment ID or Slug")
	apiURL := runCmd.String("api-url", "http://localhost:8000", "AegisVault API base URL")

	cmdArgs := os.Args[2:]
	var splitIdx = -1
	for i, arg := range cmdArgs {
		if arg == "--" {
			splitIdx = i
			break
		}
	}

	var childCommand []string
	if splitIdx != -1 {
		_ = runCmd.Parse(cmdArgs[:splitIdx])
		childCommand = cmdArgs[splitIdx+1:]
	} else {
		_ = runCmd.Parse(cmdArgs)
	}

	token := os.Getenv("AEGIS_TOKEN")
	if token == "" {
		token = "DEMO_TOKEN"
	}

	fmt.Printf("[aegis-agent] Initializing secret injection for project=%s, env=%s\n", *projectID, *envID)

	// Fetch secrets from API
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets?project_id=%s&environment_id=%s", *apiURL, *projectID, *envID), nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var secrets []SecretResponse
			if json.Unmarshal(body, &secrets) == nil {
				fmt.Printf("[aegis-agent] Injected %d authorized secrets into process environment.\n", len(secrets))
				for _, s := range secrets {
					// Reveal secret
					revReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%s/reveal", *apiURL, s.ID), nil)
					revReq.Header.Set("Authorization", "Bearer "+token)
					revResp, err := client.Do(revReq)
					if err == nil && revResp.StatusCode == 200 {
						revBody, _ := io.ReadAll(revResp.Body)
						revResp.Body.Close()
						var rev RevealResponse
						if json.Unmarshal(revBody, &rev) == nil {
							os.Setenv(rev.Key, rev.Value)
						}
					}
				}
			}
		}
	}

	if len(childCommand) == 0 {
		fmt.Println("[aegis-agent] No command specified to run. Exiting.")
		return
	}

	fmt.Printf("[aegis-agent] Spawning child process: %s\n", strings.Join(childCommand, " "))
	cmd := exec.Command(childCommand[0], childCommand[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[aegis-agent] Failed to start child process: %v\n", err)
		os.Exit(1)
	}

	go func() {
		sig := <-sigChan
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
	}()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
