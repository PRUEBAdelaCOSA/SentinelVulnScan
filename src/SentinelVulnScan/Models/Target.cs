namespace SentinelVulnScan.Models;

public class Target
{
    /// <summary>
    /// Base URL of the target website
    /// </summary>
    public string Url { get; set; } = string.Empty;
    
    /// <summary>
    /// Discovered endpoints within the target
    /// </summary>
    public List<Endpoint> Endpoints { get; set; } = new List<Endpoint>();
    
    /// <summary>
    /// Custom HTTP headers to include in requests
    /// </summary>
    public Dictionary<string, string> CustomHeaders { get; set; } = new Dictionary<string, string>();
    
    /// <summary>
    /// Cookies to include in requests
    /// </summary>
    public Dictionary<string, string> Cookies { get; set; } = new Dictionary<string, string>();
}

public class Endpoint
{
    /// <summary>
    /// URL of the endpoint
    /// </summary>
    public string Url { get; set; } = string.Empty;
    
    /// <summary>
    /// HTTP method (GET, POST, etc.)
    /// </summary>
    public string Method { get; set; } = "GET";
    
    /// <summary>
    /// Content type (application/json, application/xml, etc.)
    /// </summary>
    public string ContentType { get; set; } = string.Empty;
    
    /// <summary>
    /// Parameters found in the endpoint (GET parameters, form fields, etc.)
    /// </summary>
    public List<Parameter> Parameters { get; set; } = new List<Parameter>();
}

public class Parameter
{
    /// <summary>
    /// Name of the parameter
    /// </summary>
    public string Name { get; set; } = string.Empty;
    
    /// <summary>
    /// Type of parameter (query, form, header, etc.)
    /// </summary>
    public ParameterType Type { get; set; }
    
    /// <summary>
    /// Default or example value
    /// </summary>
    public string DefaultValue { get; set; } = string.Empty;
    
    /// <summary>
    /// Whether the parameter is required
    /// </summary>
    public bool Required { get; set; }
}

public enum ParameterType
{
    Query,
    Form,
    Cookie,
    Header,
    Path,
    Json,
    Xml
}
