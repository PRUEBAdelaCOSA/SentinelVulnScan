using SentinelVulnScan.Models;
using System.Text;

namespace SentinelVulnScan.Reports;

public class HtmlReportGenerator : IReportGenerator
{
    public async Task GenerateReportAsync(List<Vulnerability> vulnerabilities, string outputPath, string targetUrl)
    {
        var html = new StringBuilder();
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html lang=\"en\">");
        html.AppendLine("<head>");
        html.AppendLine("    <meta charset=\"UTF-8\">");
        html.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.AppendLine("    <title>SentinelVulnScan Report</title>");
        html.AppendLine("    <style>");
        html.AppendLine("        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }");
        html.AppendLine("        .container { max-width: 1200px; margin: 0 auto; }");
        html.AppendLine("        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }");
        html.AppendLine("        h2 { color: #2c3e50; margin-top: 30px; }");
        html.AppendLine("        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }");
        html.AppendLine("        .summary-item { margin: 10px 0; }");
        html.AppendLine("        .vulnerability { background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
        html.AppendLine("        .vulnerability h3 { color: #3498db; margin-top: 0; }");
        html.AppendLine("        .vulnerability-details { display: grid; grid-template-columns: 150px 1fr; gap: 10px; margin-top: 15px; }");
        html.AppendLine("        .label { font-weight: bold; color: #555; }");
        html.AppendLine("        .critical { background-color: #ffebee; border-left: 5px solid #f44336; }");
        html.AppendLine("        .high { background-color: #fff8e1; border-left: 5px solid #ffc107; }");
        html.AppendLine("        .medium { background-color: #e3f2fd; border-left: 5px solid #2196f3; }");
        html.AppendLine("        .low { background-color: #e8f5e9; border-left: 5px solid #4caf50; }");
        html.AppendLine("        .info { background-color: #f3e5f5; border-left: 5px solid #9c27b0; }");
        html.AppendLine("        .evidence { background-color: #f5f5f5; padding: 10px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; margin-top: 5px; }");
        html.AppendLine("        .footer { margin-top: 30px; text-align: center; font-size: 0.9em; color: #777; }");
        html.AppendLine("        .chart { width: 100%; max-width: 500px; margin: 20px auto; }");
        html.AppendLine("    </style>");
        html.AppendLine("</head>");
        html.AppendLine("<body>");
        html.AppendLine("    <div class=\"container\">");
        html.AppendLine($"        <h1>SentinelVulnScan Vulnerability Report</h1>");
        html.AppendLine("        <div class=\"summary\">");
        html.AppendLine($"            <div class=\"summary-item\"><strong>Target URL:</strong> {targetUrl}</div>");
        html.AppendLine($"            <div class=\"summary-item\"><strong>Scan Date:</strong> {DateTime.Now}</div>");
        html.AppendLine($"            <div class=\"summary-item\"><strong>Total Vulnerabilities Found:</strong> {vulnerabilities.Count}</div>");
        
        // Count vulnerabilities by severity
        var criticalCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.Critical);
        var highCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.High);
        var mediumCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.Medium);
        var lowCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.Low);
        var infoCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.Info);
        
        html.AppendLine($"            <div class=\"summary-item\"><strong>Critical:</strong> {criticalCount}</div>");
        html.AppendLine($"            <div class=\"summary-item\"><strong>High:</strong> {highCount}</div>");
        html.AppendLine($"            <div class=\"summary-item\"><strong>Medium:</strong> {mediumCount}</div>");
        html.AppendLine($"            <div class=\"summary-item\"><strong>Low:</strong> {lowCount}</div>");
        html.AppendLine($"            <div class=\"summary-item\"><strong>Info:</strong> {infoCount}</div>");
        html.AppendLine("        </div>");
        
        // Group vulnerabilities by type
        var vulnByType = vulnerabilities.GroupBy(v => v.Type).ToDictionary(g => g.Key, g => g.ToList());
        
        foreach (var type in vulnByType.Keys)
        {
            html.AppendLine($"        <h2>{type} Vulnerabilities ({vulnByType[type].Count})</h2>");
            
            foreach (var vuln in vulnByType[type])
            {
                var severityClass = vuln.Severity.ToString().ToLower();
                html.AppendLine($"        <div class=\"vulnerability {severityClass}\">");
                html.AppendLine($"            <h3>{vuln.Description}</h3>");
                html.AppendLine("            <div class=\"vulnerability-details\">");
                html.AppendLine($"                <div class=\"label\">Severity:</div><div>{vuln.Severity}</div>");
                html.AppendLine($"                <div class=\"label\">URL:</div><div>{vuln.Url}</div>");
                html.AppendLine($"                <div class=\"label\">Method:</div><div>{vuln.Method}</div>");
                html.AppendLine($"                <div class=\"label\">Parameter:</div><div>{vuln.Parameter}</div>");
                html.AppendLine($"                <div class=\"label\">Payload:</div><div>{vuln.Payload}</div>");
                html.AppendLine($"                <div class=\"label\">CWE ID:</div><div>{vuln.CweId}</div>");
                html.AppendLine($"                <div class=\"label\">Impact:</div><div>{vuln.Impact}</div>");
                html.AppendLine($"                <div class=\"label\">Remediation:</div><div>{vuln.Remediation}</div>");
                html.AppendLine($"                <div class=\"label\">Evidence:</div><div class=\"evidence\">{vuln.Evidence}</div>");
                html.AppendLine("            </div>");
                html.AppendLine("        </div>");
            }
        }
        
        html.AppendLine("        <div class=\"footer\">");
        html.AppendLine("            <p>Report generated by SentinelVulnScan - Web Vulnerability Scanner</p>");
        html.AppendLine($"            <p>© {DateTime.Now.Year}</p>");
        html.AppendLine("        </div>");
        html.AppendLine("    </div>");
        html.AppendLine("</body>");
        html.AppendLine("</html>");
        
        await File.WriteAllTextAsync(outputPath, html.ToString());
    }
}
