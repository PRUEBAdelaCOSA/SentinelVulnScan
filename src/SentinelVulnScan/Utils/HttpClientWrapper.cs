using SentinelVulnScan.Core;
using Serilog;

namespace SentinelVulnScan.Utils;

public class HttpClientWrapper
{
    private readonly HttpClient _httpClient;
    private readonly HttpClientHandler _handler;
    private readonly Configuration _config;
    
    public HttpClientWrapper(Configuration config)
    {
        _config = config;
        
        _handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer()
        };
        
        _httpClient = new HttpClient(_handler)
        {
            Timeout = TimeSpan.FromMilliseconds(_config.Timeout)
        };
        
        _httpClient.DefaultRequestHeaders.Add("User-Agent", _config.UserAgent);
    }
    
    public async Task<HttpResponseWrapper> GetAsync(string url)
    {
        try
        {
            if (_config.Verbose)
            {
                Log.Debug("Sending GET request to {Url}", url);
            }
            
            var response = await _httpClient.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();
            
            return new HttpResponseWrapper
            {
                StatusCode = response.StatusCode,
                Content = content,
                Headers = response.Headers.ToDictionary(h => h.Key, h => h.Value.FirstOrDefault() ?? string.Empty)
            };
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error sending GET request to {Url}", url);
            throw;
        }
    }
    
    public async Task<HttpResponseWrapper> PostAsync(string url, string content, string contentType)
    {
        try
        {
            if (_config.Verbose)
            {
                Log.Debug("Sending POST request to {Url}", url);
                Log.Debug("Content-Type: {ContentType}", contentType);
                Log.Debug("Content: {Content}", content);
            }
            
            var httpContent = new StringContent(content, System.Text.Encoding.UTF8, contentType);
            var response = await _httpClient.PostAsync(url, httpContent);
            var responseContent = await response.Content.ReadAsStringAsync();
            
            return new HttpResponseWrapper
            {
                StatusCode = response.StatusCode,
                Content = responseContent,
                Headers = response.Headers.ToDictionary(h => h.Key, h => h.Value.FirstOrDefault() ?? string.Empty)
            };
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error sending POST request to {Url}", url);
            throw;
        }
    }
    
    public void AddHeader(string name, string value)
    {
        if (_httpClient.DefaultRequestHeaders.Contains(name))
        {
            _httpClient.DefaultRequestHeaders.Remove(name);
        }
        
        _httpClient.DefaultRequestHeaders.Add(name, value);
    }
      public void AddCookie(string name, string value, string domain)
    {
        _handler.CookieContainer?.Add(new Uri(domain), new System.Net.Cookie(name, value));
    }
}

public class HttpResponseWrapper
{
    public System.Net.HttpStatusCode StatusCode { get; set; }
    public string Content { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
}
