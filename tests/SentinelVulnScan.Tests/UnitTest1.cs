using SentinelVulnScan.Core;
using SentinelVulnScan.Models;
using SentinelVulnScan.Scanners;
using Moq;

namespace SentinelVulnScan.Tests;

public class SqlInjectionScannerTests
{
    [Fact]
    public async Task ScanAsync_FindsVulnerabilities_WhenTargetHasVulnerableParameters()
    {
        // Arrange
        var config = new Configuration
        {
            TargetUrl = "https://example.com",
            RequestDelay = 0 // No delay for tests
        };
        
        var scanner = new SqlInjectionScanner(config);
        
        var target = new Target
        {
            Url = "https://example.com"
        };
        
        // Add an endpoint with a potentially vulnerable parameter
        var endpoint = new Endpoint
        {
            Url = "https://example.com/search?id=1",
            Method = "GET"
        };
        
        target.Endpoints.Add(endpoint);
        
        // Act
        var vulnerabilities = await scanner.ScanAsync(target);
        
        // Assert
        Assert.NotEmpty(vulnerabilities);
        Assert.Contains(vulnerabilities, v => v.Parameter == "id");
        Assert.Contains(vulnerabilities, v => v.Type == "SqlInjection");
        Assert.Contains(vulnerabilities, v => v.Severity == SeverityLevel.High);
    }
    
    [Fact]
    public void GetScannerName_ReturnsCorrectName()
    {
        // Arrange
        var config = new Configuration();
        var scanner = new SqlInjectionScanner(config);
        
        // Act
        var name = scanner.GetScannerName();
        
        // Assert
        Assert.Equal("SqlInjection", name);
    }
    
    [Fact]
    public void CreateVulnerability_SetsCorrectProperties()
    {
        // Arrange
        var config = new Configuration();
        var scanner = new SqlInjectionScanner(config);
        
        // Use reflection to call the protected method
        var method = typeof(BaseScanner).GetMethod("CreateVulnerability", 
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        
        // Act
        var vulnerability = (Vulnerability)method.Invoke(scanner, new object[] 
        { 
            "https://example.com", 
            "GET", 
            "id", 
            "' OR '1'='1", 
            "Error message", 
            SeverityLevel.High 
        });
        
        // Assert
        Assert.Equal("SqlInjection", vulnerability.Type);
        Assert.Equal("https://example.com", vulnerability.Url);
        Assert.Equal("GET", vulnerability.Method);
        Assert.Equal("id", vulnerability.Parameter);
        Assert.Equal("' OR '1'='1", vulnerability.Payload);
        Assert.Equal("Error message", vulnerability.Evidence);
        Assert.Equal(SeverityLevel.High, vulnerability.Severity);
        Assert.Equal("CWE-89", vulnerability.CweId);
        Assert.NotEmpty(vulnerability.Remediation);
        Assert.NotEmpty(vulnerability.Impact);
    }
}
