# SentinelVulnScan

A C# application for scanning websites for various injection vulnerabilities, including SQL injection, XSS (Cross-Site Scripting), XML injection, JSON injection, and command injection.

## Features

- Scans for multiple types of injection vulnerabilities:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - XML Injection/XXE
  - JSON Injection
  - Command Injection
- Customizable scan configuration
- Detailed vulnerability reporting
- Export reports as HTML or JSON
- Modular architecture for easy extension

## Installation

### Prerequisites

- .NET 9.0 SDK or later
- Visual Studio 2022 or Visual Studio Code with C# extensions

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/arhadnane/SentinelVulnScan.git
   ```

2. Navigate to the project directory:
   ```
   cd SentinelVulnScan
   ```

3. Build the project:
   ```
   dotnet build
   ```

## Usage

### Basic Usage

```
dotnet run --project src/SentinelVulnScan/SentinelVulnScan.csproj -u https://example.com
```

### Command Line Options

- `-u, --url` - Target URL to scan (required)
- `-d, --depth` - Scan depth (default: 2)
- `-t, --timeout` - Request timeout in milliseconds (default: 30000)
- `-o, --output` - Output report file path (default: report.html)
- `-v, --verbose` - Enable verbose output
- `--sql` - Enable SQL injection scanning (default: true)
- `--xss` - Enable XSS scanning (default: true)
- `--xml` - Enable XML injection scanning (default: true)
- `--json` - Enable JSON injection scanning (default: true)
- `--cmd` - Enable command injection scanning (default: true)

### Examples

Scan with custom depth and output file:
```
dotnet run --project src/SentinelVulnScan/SentinelVulnScan.csproj -u https://example.com -d 3 -o report.json
```

Scan only for SQL injection and XSS:
```
dotnet run --project src/SentinelVulnScan/SentinelVulnScan.csproj -u https://example.com --xml=false --json=false --cmd=false
```

## Scan Reports

SentinelVulnScan can generate reports in two formats:

- **HTML** - A detailed report with color-coding by severity level
- **JSON** - A structured report suitable for machine processing

## Vulnerable Test Server

The project includes a vulnerable test server to help you test the scanning functionality. This server contains intentional vulnerabilities for each type of injection that SentinelVulnScan can detect.

### Running the Test Environment

#### Windows
```
run_scan_test.bat
```

#### Linux/macOS
```
chmod +x run_scan_test.sh
./run_scan_test.sh
```

### Starting the Vulnerable Server Manually

```
cd VulnerableTestServer
dotnet run
```

This will start the server at http://localhost:5000 with the following vulnerabilities:

- SQL Injection: `/search?q=test` (try: `' OR '1'='1`)
- SQL Injection (Login Form): `/login-form` (try username: `admin' --`)
- XSS: `/greet?name=test` (try: `<script>alert('XSS')</script>`)
- Stored XSS: `/comments`
- XML Injection: `/xml-form` (try XXE payloads)
- JSON Injection: `/json-form` (try deserialization attacks)
- Command Injection: `/ping-form` (try: `127.0.0.1 & ipconfig`)

### Running the Scanner Against the Vulnerable Server

```
cd src/SentinelVulnScan
dotnet run --test-local
```

This will run a pre-configured scan against the local vulnerable server and generate a report.

**WARNING**: The vulnerable test server should NEVER be deployed in a production environment.

## Warning and Disclaimer

This tool should only be used on systems you own or have explicit permission to test. Unauthorized scanning of websites may be illegal in your jurisdiction.

SentinelVulnScan is designed for security professionals and developers to test their own applications for vulnerabilities. Use responsibly.

## Architecture

SentinelVulnScan is built with a modular architecture:

- **Core** - Main scanner logic and configuration
- **Scanners** - Individual vulnerability scanners
- **Models** - Data models for targets and vulnerabilities
- **Reports** - Report generation
- **Utils** - Utility functions and helpers

### Architecture Diagrams

The following architecture diagrams are available:

- [Application Architecture (Draw.io)](./SentinelVulnScan_Architecture.drawio) - Detailed application architecture diagram
- [Application Architecture (Simple)](./SentinelVulnScan_Architecture_Simple.drawio) - Simplified application architecture
- [Application Architecture (Mermaid)](./SentinelVulnScan_Architecture.mmd) - Text-based architecture diagram
- [Vulnerability Scan Flow](./SentinelVulnScan_VulnerabilityScanFlow_Simple.drawio) - Diagram of the vulnerability scanning process
- [XXE Vulnerability Scan Flow (Draw.io)](./SentinelVulnScan_XXE_ScanFlow.drawio) - Detailed flow for XML/XXE vulnerability scanning
- [XXE Vulnerability Scan Flow (Mermaid)](./SentinelVulnScan_XXE_ScanFlow.mmd) - Text-based XXE scanning flow diagram
- [Vulnerable Test Server Architecture](./VulnerableTestServer_Architecture.drawio) - Architecture of the included test server with intentional vulnerabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
