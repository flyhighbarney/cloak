package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

// cmdChat sends a prompt through the configured gateway.
// Uses the OpenAI /v1/chat/completions endpoint.
func cmdChat(args []string) error {
	fs := flag.NewFlagSet("chat", flag.ContinueOnError)
	model := fs.String("model", "gpt-4o-mini", "Model to use")
	if err := fs.Parse(args); err != nil {
		return err
	}
	prompt := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if prompt == "" {
		return errors.New(`usage: policyctl chat "your prompt here"`)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	client := newClient(cfg)

	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type req struct {
		Model    string `json:"model"`
		Messages []msg  `json:"messages"`
	}
	type choice struct {
		Message msg `json:"message"`
	}
	type response struct {
		Model   string   `json:"model"`
		Choices []choice `json:"choices"`
	}

	in := req{
		Model:    *model,
		Messages: []msg{{Role: "user", Content: prompt}},
	}
	var out response
	if err := client.postJSON("/v1/chat/completions", in, &out); err != nil {
		return err
	}
	if len(out.Choices) == 0 {
		return errors.New("empty response")
	}
	fmt.Println(out.Choices[0].Message.Content)
	return nil
}
