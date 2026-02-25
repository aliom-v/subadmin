package sublink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

type convertRequest struct {
	Target  string `json:"target"`
	Content string `json:"content"`
}

type convertResponse struct {
	Data string `json:"data"`
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) Convert(ctx context.Context, target string, nodes []string) (string, error) {
	if len(nodes) == 0 {
		return "", nil
	}
	payload := strings.Join(nodes, "\n")
	if c.baseURL == "" {
		return fallbackOutput(target, payload), nil
	}

	body, err := json.Marshal(convertRequest{Target: target, Content: payload})
	if err != nil {
		return "", fmt.Errorf("marshal convert request: %w", err)
	}

	endpoint := c.baseURL + "/convert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build convert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fallbackOutput(target, payload), nil
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read convert response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fallbackOutput(target, payload), nil
	}

	var parsed convertResponse
	if err := json.Unmarshal(respData, &parsed); err == nil && strings.TrimSpace(parsed.Data) != "" {
		return parsed.Data, nil
	}

	trimmed := strings.TrimSpace(string(respData))
	if trimmed == "" {
		return "", nil
	}
	return trimmed, nil
}

func fallbackOutput(target, content string) string {
	return fmt.Sprintf("# fallback output for %s\n%s\n", target, content)
}
