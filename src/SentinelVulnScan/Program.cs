using CommandLine;
using CommandLine.Text;
using SentinelVulnScan.Core;
using Serilog;

namespace SentinelVulnScan;

class Program
{
    public class Options
    {
        [Option('u', "url", Required = false, HelpText = "Target URL to scan.")]
        public string TargetUrl { get; set; } = string.Empty;

        [Option('d', "depth", Required = false, Default = 2, HelpText = "Scan depth (levels of links to follow).")]
        public int ScanDepth { get; set; }

        [Option('t', "timeout", Required = false, Default = 30000, HelpText = "Request timeout in milliseconds.")]
        public int Timeout { get; set; }

        [Option('o', "output", Required = false, Default = "report.html", HelpText = "Output report file path.")]
        public string OutputPath { get; set; } = string.Empty;

        [Option('v', "verbose", Required = false, Default = false, HelpText = "Set output to verbose.")]
        public bool Verbose { get; set; }
        
        [Option("sql", Required = false, Default = true, HelpText = "Enable SQL injection scanning.")]
        public bool SqlInjection { get; set; }
        
        [Option("xss", Required = false, Default = true, HelpText = "Enable XSS scanning.")]
        public bool XssInjection { get; set; }
        
        [Option("xml", Required = false, Default = true, HelpText = "Enable XML injection scanning.")]
        public bool XmlInjection { get; set; }
        
        [Option("json", Required = false, Default = true, HelpText = "Enable JSON injection scanning.")]
        public bool JsonInjection { get; set; }

        [Option("cmd", Required = false, Default = true, HelpText = "Enable command injection scanning.")]
        public bool CommandInjection { get; set; }
        
        [Option("test-local", Required = false, Default = false, HelpText = "Run a test scan against the local vulnerable test server.")]
        public bool TestLocalServer { get; set; }
    }

    static async Task<int> Main(string[] args)
    {
        // Configure logging
        ConfigureLogging();

        var parser = new Parser(with => with.HelpWriter = null);
        var parserResult = parser.ParseArguments<Options>(args);
        
        return await parserResult.MapResult(
            async (Options opts) => await RunScanAsync(opts),
            errs => Task.FromResult(DisplayHelp(parserResult))
        );
    }

    private static void ConfigureLogging()
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .WriteTo.File("scan-log.txt", rollingInterval: RollingInterval.Day)
            .CreateLogger();
    }    private static async Task<int> RunScanAsync(Options options)
    {
        try
        {
            Log.Information("Starting SentinelVulnScan...");
            
            // Check if we should run the local test scan
            if (options.TestLocalServer)
            {
                Log.Information("Running test scan against local vulnerable test server...");
                await TestScan.TestScanLocalhost.RunScanAsync();
                return 0;
            }
            
            // Regular scan logic
            if (string.IsNullOrEmpty(options.TargetUrl))
            {
                Log.Error("Target URL is required when not using --test-local");
                return 1;
            }
            
            Log.Information("Target URL: {Url}", options.TargetUrl);
            
            var config = new Configuration
            {
                TargetUrl = options.TargetUrl,
                ScanDepth = options.ScanDepth,
                Timeout = options.Timeout,
                OutputPath = options.OutputPath,
                Verbose = options.Verbose,
                EnabledScanners = new Dictionary<string, bool>
                {
                    { "SqlInjection", options.SqlInjection },
                    { "XssInjection", options.XssInjection },
                    { "XmlInjection", options.XmlInjection },
                    { "JsonInjection", options.JsonInjection },
                    { "CommandInjection", options.CommandInjection }
                }
            };

            var scanner = new Scanner(config);
            var results = await scanner.ScanAsync();
            
            Log.Information("Scan completed. Found {Count} vulnerabilities.", results.Count);
            
            // Generate and save report
            var reporter = new Reporter(config);
            await reporter.GenerateReportAsync(results);
            
            Log.Information("Report saved to {Path}", options.OutputPath);
            return 0;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "An error occurred during scanning");
            return 1;
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    private static int DisplayHelp<T>(ParserResult<T> result)
    {
        var helpText = HelpText.AutoBuild(result, h =>
        {
            h.AdditionalNewLineAfterOption = false;
            h.Heading = "SentinelVulnScan 1.0.0";
            h.Copyright = "Copyright (c) 2025";
            return HelpText.DefaultParsingErrorsHandler(result, h);
        }, e => e);
        Console.WriteLine(helpText);
        return 1;
    }
}
