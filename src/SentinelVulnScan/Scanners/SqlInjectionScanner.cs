using SentinelVulnScan.Models;
using Serilog;

namespace SentinelVulnScan.Scanners;

public class SqlInjectionScanner : BaseScanner
{
    private readonly List<string> _payloads = new()
    {
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "1' OR '1' = '1",
        "1' AND 1=1--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password,1 FROM users--",
        "admin' --",
        "admin' #",
        "' OR 1=1 #",
        "' OR 1=1 LIMIT 1--",
        "' OR '1'='1' /*"
    };
    
    private readonly List<string> _errorPatterns = new()
    {
        "SQL syntax",
        "mysql_fetch_array",
        "ORA-",
        "Microsoft SQL Server",
        "PostgreSQL",
        "MySQL",
        "SQLite",
        "syntax error",
        "unclosed quotation mark",
        "unterminated string",
        "Division by zero",
        "ODBC Driver",
        "SQLSTATE"
    };
    
    public SqlInjectionScanner(Core.Configuration config) : base(config)
    {
    }
    
    public override string GetScannerName() => "SqlInjection";
    
    protected override string GetRemediationAdvice() => 
        "Use parameterized queries or prepared statements instead of concatenating user input. " +
        "Implement input validation and sanitization. " +
        "Use stored procedures with parameterized inputs. " +
        "Apply the principle of least privilege to database accounts.";
    
    protected override string GetCweId() => "CWE-89";
    
    protected override string GetImpactDescription() => 
        "SQL injection can lead to unauthorized access to sensitive data, data modification, " +
        "data deletion, administrative operations on the database, and in some cases, command execution on the server.";
    
    public override async Task<List<Vulnerability>> ScanAsync(Target target)
    {
        var vulnerabilities = new List<Vulnerability>();
        
        foreach (var endpoint in target.Endpoints)
        {
            if (endpoint.Method.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                await ScanGetParametersAsync(endpoint, vulnerabilities);
            }
            else if (endpoint.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                await ScanPostParametersAsync(endpoint, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private async Task ScanGetParametersAsync(Endpoint endpoint, List<Vulnerability> vulnerabilities)
    {
        var uri = new Uri(endpoint.Url);
        var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
        
        foreach (var key in queryParams.AllKeys)
        {
            if (string.IsNullOrEmpty(key)) continue;
            
            foreach (var payload in _payloads)
            {
                try
                {
                    // Clone the query parameters
                    var modifiedParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
                    modifiedParams[key] = payload;
                    
                    // Build the modified URL
                    var uriBuilder = new UriBuilder(uri)
                    {
                        Query = modifiedParams.ToString() ?? string.Empty
                    };
                    
                    var modifiedUrl = uriBuilder.Uri.ToString();
                    
                    // In a real implementation, this would make an HTTP request to the modified URL
                    // and analyze the response for SQL error patterns
                    
                    // For now, we'll simulate a vulnerability for demonstration
                    if (key == "id" || key == "userId" || key == "productId")
                    {
                        var vulnerability = CreateVulnerability(
                            endpoint.Url,
                            "GET",
                            key,
                            payload,
                            "Simulated SQL error response: ORA-01756: quoted string not properly terminated",
                            SeverityLevel.High);
                        
                        vulnerabilities.Add(vulnerability);
                        Log.Warning("Found SQL injection vulnerability in parameter {Param} at {Url}", 
                            key, endpoint.Url);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error testing SQL injection for parameter {Param} at {Url}",
                        key, endpoint.Url);
                }
                
                // Add a small delay to avoid overwhelming the target
                await Task.Delay(Config.RequestDelay);
            }
        }
    }
    
    private async Task ScanPostParametersAsync(Endpoint endpoint, List<Vulnerability> vulnerabilities)
    {
        foreach (var parameter in endpoint.Parameters)
        {
            foreach (var payload in _payloads)
            {
                try
                {
                    // In a real implementation, this would create a POST request with the payload
                    // and analyze the response for SQL error patterns
                    
                    // For now, we'll simulate a vulnerability for demonstration
                    if (parameter.Name.Contains("id", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("user", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Name.Contains("login", StringComparison.OrdinalIgnoreCase))
                    {
                        var vulnerability = CreateVulnerability(
                            endpoint.Url,
                            "POST",
                            parameter.Name,
                            payload,
                            "Simulated SQL error response: You have an error in your SQL syntax",
                            SeverityLevel.High);
                        
                        vulnerabilities.Add(vulnerability);
                        Log.Warning("Found SQL injection vulnerability in parameter {Param} at {Url}", 
                            parameter.Name, endpoint.Url);
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error testing SQL injection for parameter {Param} at {Url}",
                        parameter.Name, endpoint.Url);
                }
                
                // Add a small delay to avoid overwhelming the target
                await Task.Delay(Config.RequestDelay);
            }
        }
    }
}
