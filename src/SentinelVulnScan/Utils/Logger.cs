using Serilog;

namespace SentinelVulnScan.Utils;

/// <summary>
/// Utility class for logging
/// </summary>
public class Logger
{
    /// <summary>
    /// Initialize the logger with console and file outputs
    /// </summary>
    /// <param name="logFilePath">Path to the log file</param>
    /// <param name="verbose">Whether to log verbose messages</param>
    public static void Initialize(string logFilePath = "scan-log.txt", bool verbose = false)
    {
        var logConfig = new LoggerConfiguration()
            .WriteTo.Console()
            .WriteTo.File(logFilePath, rollingInterval: RollingInterval.Day);
        
        if (verbose)
        {
            logConfig.MinimumLevel.Debug();
        }
        else
        {
            logConfig.MinimumLevel.Information();
        }
        
        Log.Logger = logConfig.CreateLogger();
        
        Log.Information("Logger initialized");
    }
    
    /// <summary>
    /// Close and flush the logger
    /// </summary>
    public static void Close()
    {
        Log.CloseAndFlush();
    }
}
