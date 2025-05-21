using SentinelVulnScan.Models;

namespace SentinelVulnScan.Reports;

public interface IReportGenerator
{
    Task GenerateReportAsync(List<Vulnerability> vulnerabilities, string outputPath, string targetUrl);
}
