using SentinelVulnScan.Models;
using SentinelVulnScan.Scanners;
using Serilog;

namespace SentinelVulnScan.Core;

public class Scanner
{
    private readonly Configuration _config;
    private readonly List<BaseScanner> _scanners = new();
    
    public Scanner(Configuration config)
    {
        _config = config;
        InitializeScanners();
    }
    
    private void InitializeScanners()
    {
        if (_config.EnabledScanners.TryGetValue("SqlInjection", out bool sqlEnabled) && sqlEnabled)
        {
            _scanners.Add(new SqlInjectionScanner(_config));
        }
        
        if (_config.EnabledScanners.TryGetValue("XssInjection", out bool xssEnabled) && xssEnabled)
        {
            _scanners.Add(new XssScanner(_config));
        }
        
        if (_config.EnabledScanners.TryGetValue("XmlInjection", out bool xmlEnabled) && xmlEnabled)
        {
            _scanners.Add(new XmlInjectionScanner(_config));
        }
        
        if (_config.EnabledScanners.TryGetValue("JsonInjection", out bool jsonEnabled) && jsonEnabled)
        {
            _scanners.Add(new JsonInjectionScanner(_config));
        }
        
        if (_config.EnabledScanners.TryGetValue("CommandInjection", out bool cmdEnabled) && cmdEnabled)
        {
            _scanners.Add(new CommandInjectionScanner(_config));
        }
    }
    
    public async Task<List<Vulnerability>> ScanAsync()
    {
        var target = new Target
        {
            Url = _config.TargetUrl
        };
        
        Log.Information("Starting scan of {Url}", target.Url);
        
        // Collect all discovered URLs
        await DiscoverUrlsAsync(target);
        
        Log.Information("Discovered {Count} endpoints to scan", target.Endpoints.Count);
        
        var allVulnerabilities = new List<Vulnerability>();
        
        // Run each scanner on the target
        foreach (var scanner in _scanners)
        {
            Log.Information("Running {Scanner} scanner...", scanner.GetType().Name);
            var vulnerabilities = await scanner.ScanAsync(target);
            allVulnerabilities.AddRange(vulnerabilities);
            
            Log.Information("{Scanner} found {Count} vulnerabilities", 
                scanner.GetType().Name, 
                vulnerabilities.Count);
        }
        
        return allVulnerabilities;
    }
    
    private async Task DiscoverUrlsAsync(Target target)
    {
        // This would crawl the website to identify forms, input fields, and other injection points
        // For simplicity, we'll just add the target URL as a single endpoint
        
        target.Endpoints.Add(new Endpoint
        {
            Url = target.Url,
            Method = "GET"
        });
        
        // In a real implementation, this would:
        // 1. Parse the HTML of the target URL
        // 2. Identify forms and their input fields
        // 3. Identify JavaScript-based endpoints
        // 4. Discover links to other pages within the same domain
        // 5. Recursively crawl those pages up to the configured depth
        
        await Task.CompletedTask;
    }
    
    public async Task<List<Vulnerability>> ScanTarget(Target target)
    {
        Log.Information("Starting scan of pre-configured target {Url}", target.Url);
        Log.Information("Target has {Count} pre-configured endpoints", target.Endpoints.Count);
        
        var allVulnerabilities = new List<Vulnerability>();
        
        // Run each scanner on the target
        foreach (var scanner in _scanners)
        {
            Log.Information("Running {Scanner} scanner...", scanner.GetType().Name);
            var vulnerabilities = await scanner.ScanAsync(target);
            allVulnerabilities.AddRange(vulnerabilities);
            
            Log.Information("{Scanner} found {Count} vulnerabilities", 
                scanner.GetType().Name, 
                vulnerabilities.Count);
        }
        
        return allVulnerabilities;
    }
}
