using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using SentinelVulnScan.Models;

namespace SentinelVulnScan.Reports;

public class JsonReportGenerator : IReportGenerator
{
    public async Task GenerateReportAsync(List<Vulnerability> vulnerabilities, string outputPath, string targetUrl)
    {
        var report = new
        {
            ScanInfo = new
            {
                TargetUrl = targetUrl,
                ScanDate = DateTime.Now,
                TotalVulnerabilities = vulnerabilities.Count
            },
            SeveritySummary = new
            {
                Critical = vulnerabilities.Count(v => v.Severity == SeverityLevel.Critical),
                High = vulnerabilities.Count(v => v.Severity == SeverityLevel.High),
                Medium = vulnerabilities.Count(v => v.Severity == SeverityLevel.Medium),
                Low = vulnerabilities.Count(v => v.Severity == SeverityLevel.Low),
                Info = vulnerabilities.Count(v => v.Severity == SeverityLevel.Info)
            },
            Vulnerabilities = vulnerabilities
        };
        
        var jsonSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            Converters = { new StringEnumConverter() }
        };
        
        var json = JsonConvert.SerializeObject(report, jsonSettings);
        await File.WriteAllTextAsync(outputPath, json);
    }
}
