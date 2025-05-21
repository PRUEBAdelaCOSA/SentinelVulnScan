using SentinelVulnScan.Models;

namespace SentinelVulnScan.Core;

public class Configuration
{
    /// <summary>
    /// The target URL to scan
    /// </summary>
    public string TargetUrl { get; set; } = string.Empty;
    
    /// <summary>
    /// Scan depth (levels of links to follow)
    /// </summary>
    public int ScanDepth { get; set; } = 2;
    
    /// <summary>
    /// Request timeout in milliseconds
    /// </summary>
    public int Timeout { get; set; } = 30000;
    
    /// <summary>
    /// Output report file path
    /// </summary>
    public string OutputPath { get; set; } = "report.html";
    
    /// <summary>
    /// Verbose output
    /// </summary>
    public bool Verbose { get; set; } = false;
    
    /// <summary>
    /// Dictionary of enabled scanner types
    /// </summary>
    public Dictionary<string, bool> EnabledScanners { get; set; } = new Dictionary<string, bool>();
    
    /// <summary>
    /// Maximum concurrent requests
    /// </summary>
    public int MaxConcurrentRequests { get; set; } = 5;
    
    /// <summary>
    /// Delay between requests in milliseconds
    /// </summary>
    public int RequestDelay { get; set; } = 100;
    
    /// <summary>
    /// User agent to use for requests
    /// </summary>
    public string UserAgent { get; set; } = "SentinelVulnScan/1.0.0";
}
