package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go_react2shell/internal/scanner"
)

// Colors for terminal output
var (
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Cyan   = "\033[96m"
	Gray   = "\033[90m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

// DisableColors removes color codes
func DisableColors() {
	Red = ""
	Green = ""
	Yellow = ""
	Cyan = ""
	Gray = ""
	Bold = ""
	Reset = ""
}

// PrintBanner prints the tool banner
func PrintBanner() {
	banner := fmt.Sprintf(`
%s%sReact2Shell Scanner - Go Edition%s
%sCVE-2025-55182 & CVE-2025-66478%s
%sbrought to you by assetnote%s
`, Bold, Cyan, Reset, Cyan, Reset, Cyan, Reset)
	fmt.Println(banner)
}

// PrintResult prints a scan result to the terminal
func PrintResult(result scanner.Result, verbose bool) {
	host := result.Host
	finalURL := result.FinalURL
	testedURL := result.TestedURL
	redirected := finalURL != "" && testedURL != "" && finalURL != testedURL

	if result.Vulnerable != nil && *result.Vulnerable {
		status := fmt.Sprintf("%s%s[VULNERABLE]%s", Red, Bold, Reset)
		statusCode := 0
		if result.StatusCode != nil {
			statusCode = *result.StatusCode
		}
		fmt.Printf("%s %s - Status: %d\n", status, host, statusCode)
		if redirected {
			fmt.Printf("  -> Redirected to: %s\n", finalURL)
		}
	} else if result.Vulnerable != nil && !*result.Vulnerable {
		status := fmt.Sprintf("%s[NOT VULNERABLE]%s", Green, Reset)
		if result.StatusCode != nil {
			fmt.Printf("%s %s - Status: %d\n", status, host, *result.StatusCode)
		} else {
			errMsg := result.Error
			if errMsg != "" {
				fmt.Printf("%s %s - %s\n", status, host, errMsg)
			} else {
				fmt.Printf("%s %s\n", status, host)
			}
		}
		if redirected && verbose {
			fmt.Printf("  -> Redirected to: %s\n", finalURL)
		}
	} else {
		status := fmt.Sprintf("%s[ERROR]%s", Yellow, Reset)
		errMsg := result.Error
		if errMsg == "" {
			errMsg = "Unknown error"
		}
		fmt.Printf("%s %s - %s\n", status, host, errMsg)
	}

	if verbose && result.Response != "" {
		fmt.Printf("  %sResponse snippet:%s\n", Cyan, Reset)
		lines := strings.Split(result.Response, "\r\n")
		for i, line := range lines {
			if i >= 10 {
				break
			}
			fmt.Printf("    %s\n", line)
		}
	}
}

// ScanOutput represents the JSON output format
type ScanOutput struct {
	ScanTime     string           `json:"scan_time"`
	TotalResults int              `json:"total_results"`
	Results      []scanner.Result `json:"results"`
}

// SaveResults saves scan results to a JSON file
func SaveResults(results []scanner.Result, outputFile string, vulnerableOnly bool) error {
	if vulnerableOnly {
		var filtered []scanner.Result
		for _, r := range results {
			if r.Vulnerable != nil && *r.Vulnerable {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	output := ScanOutput{
		ScanTime:     time.Now().UTC().Format(time.RFC3339),
		TotalResults: len(results),
		Results:      results,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("\n%s[+] Results saved to: %s%s\n", Green, outputFile, Reset)
	return nil
}

// PrintSummary prints the scan summary
func PrintSummary(total, vulnerable, errors int) {
	fmt.Println()
	fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("=", 60), Reset)
	fmt.Printf("%sSCAN SUMMARY%s\n", Bold, Reset)
	fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("=", 60), Reset)
	fmt.Printf("  Total hosts scanned: %d\n", total)

	if vulnerable > 0 {
		fmt.Printf("  %s%sVulnerable: %d%s\n", Red, Bold, vulnerable, Reset)
	} else {
		fmt.Printf("  Vulnerable: %d\n", vulnerable)
	}

	fmt.Printf("  Not vulnerable: %d\n", total-vulnerable-errors)
	fmt.Printf("  Errors: %d\n", errors)
	fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("=", 60), Reset)
}
