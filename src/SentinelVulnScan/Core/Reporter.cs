using SentinelVulnScan.Models;
using SentinelVulnScan.Reports;
using Serilog;

namespace SentinelVulnScan.Core;

public class Reporter
{
    private readonly Configuration _config;
    
    public Reporter(Configuration config)
    {
        _config = config;
    }
    
    public async Task GenerateReportAsync(List<Vulnerability> vulnerabilities)
    {
        try
        {
            IReportGenerator generator;
            
            // Determine report type based on file extension
            if (_config.OutputPath.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
            {
                generator = new HtmlReportGenerator();
            }
            else if (_config.OutputPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                generator = new JsonReportGenerator();
            }
            else
            {
                // Default to HTML
                generator = new HtmlReportGenerator();
            }
            
            await generator.GenerateReportAsync(vulnerabilities, _config.OutputPath, _config.TargetUrl);
            Log.Information("Report generated successfully at {FilePath}", _config.OutputPath);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error generating report");
            throw;
        }
    }
}
