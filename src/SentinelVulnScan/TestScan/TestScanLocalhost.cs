using SentinelVulnScan.Core;
using SentinelVulnScan.Models;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;

namespace SentinelVulnScan.TestScan
{
    public class TestScanLocalhost
    {
        public static async Task RunScanAsync()
        {
            Console.WriteLine("Starting SentinelVulnScan test against local vulnerable server...");
            
            // First check if the vulnerable server is running
            bool isServerRunning = await IsServerRunningAsync();
            if (!isServerRunning)
            {
                Console.WriteLine("ERROR: The vulnerable test server is not running. Please start it first.");
                Console.WriteLine("You can start it by running the VulnerableTestServer project in another terminal.");
                return;
            }
            
            Console.WriteLine("Vulnerable server is running. Proceeding with the scan...");
            
            var config = new Configuration
            {
                TargetUrl = "http://localhost:5000",
                ScanDepth = 3,
                Timeout = 30000,
                OutputPath = "local_scan_report.html",
                Verbose = true,
                EnabledScanners = new Dictionary<string, bool>
                {
                    { "SqlInjection", true },
                    { "XssInjection", true },
                    { "XmlInjection", true },
                    { "JsonInjection", true },
                    { "CommandInjection", true }
                }
            };
            
            Console.WriteLine("Creating scanner...");
            var scanner = new Scanner(config);
            
            // Manually create a target with known endpoints from our vulnerable server
            var target = new Target
            {
                Url = "http://localhost:5000"
            };
            
            // Add vulnerable endpoints
            
            // SQL Injection endpoints
            target.Endpoints.Add(new Endpoint
            {
                Url = "http://localhost:5000/search?q=test",
                Method = "GET",
                Parameters = new List<Parameter>
                {
                    new Parameter { Name = "q", Type = ParameterType.Query, DefaultValue = "test" }
                }
            });
            
            target.Endpoints.Add(new Endpoint
            {
                Url = "http://localhost:5000/login",
                Method = "POST",
                ContentType = "application/x-www-form-urlencoded",
                Parameters = new List<Parameter>
                {
                    new Parameter { Name = "username", Type = ParameterType.Form, DefaultValue = "user" },
                    new Parameter { Name = "password", Type = ParameterType.Form, DefaultValue = "pass" }
                }
            });
            
            // XSS endpoints
            target.Endpoints.Add(new Endpoint
            {
                Url = "http://localhost:5000/greet?name=test",
                Method = "GET",
                Parameters = new List<Parameter>
                {
                    new Parameter { Name = "name", Type = ParameterType.Query, DefaultValue = "test" }
                }
            });
            
            // XML Injection endpoints
            target.Endpoints.Add(new Endpoint
            {
                Url = "http://localhost:5000/process-xml",
                Method = "POST",
                ContentType = "application/xml",
                Parameters = new List<Parameter>
                {
                    new Parameter { Name = "xml", Type = ParameterType.Xml, DefaultValue = "<?xml version=\"1.0\"?><root><data>test</data></root>" }
                }
            });
            
            // JSON Injection endpoints
            target.Endpoints.Add(new Endpoint
            {
                Url = "http://localhost:5000/process-json",
                Method = "POST",
                ContentType = "application/json",
                Parameters = new List<Parameter>
                {
                    new Parameter { Name = "json", Type = ParameterType.Json, DefaultValue = "{\"value\":\"test\"}" }
                }
            });
            
            // Command Injection endpoints
            target.Endpoints.Add(new Endpoint
            {
                Url = "http://localhost:5000/ping?host=localhost",
                Method = "GET",
                Parameters = new List<Parameter>
                {
                    new Parameter { Name = "host", Type = ParameterType.Query, DefaultValue = "localhost" }
                }
            });
            
            Console.WriteLine("Running scan on local vulnerable server...");
            var vulnerabilities = await scanner.ScanTarget(target);
            
            Console.WriteLine($"Scan completed. Found {vulnerabilities.Count} vulnerabilities:");
            
            foreach (var vulnType in vulnerabilities.GroupBy(v => v.Type))
            {
                Console.WriteLine($"- {vulnType.Key}: {vulnType.Count()} vulnerabilities");
                  // Print details of each vulnerability
                int count = 1;
                foreach (var vuln in vulnType)
                {
                    Console.WriteLine($"  {count}. {vuln.Description}");
                    Console.WriteLine($"     URL: {vuln.Url}");
                    Console.WriteLine($"     Severity: {vuln.Severity}");
                    Console.WriteLine($"     Parameter: {vuln.Parameter}");
                    count++;
                }
            }
            
            // Generate report
            var reporter = new Reporter(config);
            await reporter.GenerateReportAsync(vulnerabilities);
            
            Console.WriteLine($"Report saved to {config.OutputPath}");
        }
        
        private static async Task<bool> IsServerRunningAsync()
        {
            try
            {
                using var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);
                var response = await httpClient.GetAsync("http://localhost:5000");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
