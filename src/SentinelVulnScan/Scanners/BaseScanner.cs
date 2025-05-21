using SentinelVulnScan.Models;

namespace SentinelVulnScan.Scanners;

public abstract class BaseScanner
{
    protected readonly Core.Configuration Config;
    
    protected BaseScanner(Core.Configuration config)
    {
        Config = config;
    }
    
    /// <summary>
    /// Scan a target for vulnerabilities
    /// </summary>
    /// <param name="target">The target to scan</param>
    /// <returns>A list of discovered vulnerabilities</returns>
    public abstract Task<List<Vulnerability>> ScanAsync(Target target);
    
    /// <summary>
    /// Get a name for this scanner type
    /// </summary>
    /// <returns>Scanner name</returns>
    public abstract string GetScannerName();
    
    /// <summary>
    /// Check if this scanner is enabled in the configuration
    /// </summary>
    /// <returns>True if enabled</returns>
    protected bool IsEnabled()
    {
        return Config.EnabledScanners.TryGetValue(GetScannerName(), out bool enabled) && enabled;
    }
    
    /// <summary>
    /// Generate common remediation advice for this vulnerability type
    /// </summary>
    /// <returns>Remediation advice</returns>
    protected abstract string GetRemediationAdvice();
    
    /// <summary>
    /// Get the CWE ID for this vulnerability type
    /// </summary>
    /// <returns>CWE ID</returns>
    protected abstract string GetCweId();
    
    /// <summary>
    /// Get the impact description for this vulnerability type
    /// </summary>
    /// <returns>Impact description</returns>
    protected abstract string GetImpactDescription();
    
    /// <summary>
    /// Helper method to create a Vulnerability object with common fields filled in
    /// </summary>
    protected Vulnerability CreateVulnerability(
        string url,
        string method,
        string parameter,
        string payload,
        string evidence,
        SeverityLevel severity)
    {
        return new Vulnerability
        {
            Type = GetScannerName(),
            Description = $"{GetScannerName()} vulnerability found in {parameter} parameter",
            Severity = severity,
            Url = url,
            Method = method,
            Parameter = parameter,
            Payload = payload,
            Evidence = evidence,
            Impact = GetImpactDescription(),
            Remediation = GetRemediationAdvice(),
            CweId = GetCweId(),
            DiscoveredAt = DateTime.UtcNow
        };
    }
}
