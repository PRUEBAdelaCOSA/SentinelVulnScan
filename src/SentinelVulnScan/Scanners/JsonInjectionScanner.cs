using SentinelVulnScan.Models;
using Serilog;

namespace SentinelVulnScan.Scanners;

public class JsonInjectionScanner : BaseScanner
{
    private readonly List<string> _payloads = new()
    {
        "\"}\", {\"malicious\": \"payload",
        "{\"__proto__\": {\"polluted\": true}}",
        "{\"constructor\": {\"prototype\": {\"polluted\": true}}}",
        "{\"user\": \"admin\", \"role\": \"administrator\"}",
        "{\"$where\": \"this.a == 1\"}",
        "{\"$gt\": \"\"}",
        "{\"\": {\"$ne\": null}}",
        "{\"$regex\": \"^a\"}",
        "{\"user\": {\"$exists\": true}}",
        "{\"user\": {\"$nin\": [\"user1\", \"user2\"]}}",
        "{\"\": {\"$where\": \"sleep(5000)\"}}",
        "{\"$ne\": 1}",
        // Payloads targeting NoSQL injection
        "{\"username\": {\"$regex\": \"admin\", \"$options\": \"i\"}}",
        "{\"username\": \"admin\", \"password\": {\"$ne\": \"\"}}",
        "{\"username\": {\"$in\": [\"admin\", \"root\", \"superuser\"]}}",
        // JSON Interoperability payloads
        "{\"__proto__\": {\"isAdmin\": true}}",
        "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}"
    };
    
    public JsonInjectionScanner(Core.Configuration config) : base(config)
    {
    }
    
    public override string GetScannerName() => "JsonInjection";
    
    protected override string GetRemediationAdvice() => 
        "Validate the structure and data types of JSON input. " +
        "Implement JSON schema validation. " +
        "Use safe deserialization libraries and keep them updated. " +
        "For MongoDB or NoSQL databases, use parameterized queries or sanitize inputs. " +
        "Implement proper access controls and input sanitization.";
    
    protected override string GetCweId() => "CWE-20";
    
    protected override string GetImpactDescription() => 
        "JSON Injection can lead to data manipulation, bypassing of authentication, " +
        "privilege escalation, and in some cases, denial of service. " +
        "It can also enable prototype pollution in JavaScript applications " +
        "and NoSQL injection in document databases.";
    
    public override async Task<List<Vulnerability>> ScanAsync(Target target)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        foreach (var endpoint in target.Endpoints)
        {
            // JSON injection is mostly relevant for POST endpoints with JSON content
            if (endpoint.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
                (endpoint.ContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                await ScanJsonEndpointAsync(endpoint, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private async Task ScanJsonEndpointAsync(Endpoint endpoint, List<Vulnerability> vulnerabilities)
    {
        foreach (var payload in _payloads)
        {
            try
            {
                // In a real implementation, this would make a POST request with the JSON payload
                // and analyze the response for signs of JSON Injection vulnerability
                
                // For now, we'll simulate a vulnerability for demonstration
                if (endpoint.Url.Contains("/api/", StringComparison.OrdinalIgnoreCase) ||
                    endpoint.Url.Contains("json", StringComparison.OrdinalIgnoreCase) ||
                    endpoint.Url.Contains("rest", StringComparison.OrdinalIgnoreCase))
                {
                    var vulnerability = CreateVulnerability(
                        endpoint.Url,
                        "POST",
                        "JSON Body",
                        payload,
                        "Simulated response indicates successful JSON injection",
                        SeverityLevel.High);
                    
                    vulnerabilities.Add(vulnerability);
                    Log.Warning("Found JSON Injection vulnerability at {Url}", endpoint.Url);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error testing JSON injection at {Url}", endpoint.Url);
            }
            
            // Add a small delay to avoid overwhelming the target
            await Task.Delay(Config.RequestDelay);
        }
    }
}
