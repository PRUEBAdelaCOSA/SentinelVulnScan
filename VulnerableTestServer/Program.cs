using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Text;
using System.Xml;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();

// Configure CORS to allow any client to connect
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Use CORS
app.UseCors();

// Setup in-memory SQLite for demo purposes
using (var connection = new SqliteConnection("Data Source=:memory:"));

// Home page
app.MapGet("/", () => Results.Content(GetHomePage(), "text/html"));

#region SQL Injection Vulnerabilities

// SQL Injection vulnerability in GET parameter
app.MapGet("/search", (string q) =>
{
    var searchResults = new List<string>();
    try
    {
        // Vulnerable code - direct string concatenation
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        
        // Create a test table
        var createCmd = connection.CreateCommand();
        createCmd.CommandText = "CREATE TABLE IF NOT EXISTS products (id INTEGER, name TEXT, description TEXT)";
        createCmd.ExecuteNonQuery();
        
        // Insert some test data
        var insertCmd = connection.CreateCommand();
        insertCmd.CommandText = @"
            INSERT OR IGNORE INTO products VALUES (1, 'Phone', 'A smartphone');
            INSERT OR IGNORE INTO products VALUES (2, 'Laptop', 'A laptop computer');
            INSERT OR IGNORE INTO products VALUES (3, 'Tablet', 'A tablet device');
        ";
        insertCmd.ExecuteNonQuery();
        
        // Vulnerable query
        var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'";
        
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            searchResults.Add($"Product: {reader.GetString(1)}, Description: {reader.GetString(2)}");
        }
    }
    catch (Exception ex)
    {
        // Returning error messages is also a vulnerability
        searchResults.Add($"Error: {ex.Message}");
    }
    
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Search Results</title></head><body>");
    html.AppendLine("<h1>Search Results</h1>");
    html.AppendLine($"<p>You searched for: {q}</p>");
    html.AppendLine("<ul>");
    
    foreach (var result in searchResults)
    {
        html.AppendLine($"<li>{result}</li>");
    }
    
    html.AppendLine("</ul>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// SQL Injection vulnerability in POST parameter
app.MapPost("/login", async (HttpContext context) =>
{
    string username = "";
    string password = "";
    
    // Get form values
    if (context.Request.HasFormContentType)
    {
        var form = await context.Request.ReadFormAsync();
        username = form["username"];
        password = form["password"];
    }
    
    var result = "";
    
    try
    {
        // Vulnerable code - direct string concatenation
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        
        // Create a test table
        var createCmd = connection.CreateCommand();
        createCmd.CommandText = "CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT, is_admin INTEGER)";
        createCmd.ExecuteNonQuery();
        
        // Insert some test data
        var insertCmd = connection.CreateCommand();
        insertCmd.CommandText = @"
            INSERT OR IGNORE INTO users VALUES (1, 'admin', 'secretpassword', 1);
            INSERT OR IGNORE INTO users VALUES (2, 'user', 'userpass', 0);
        ";
        insertCmd.ExecuteNonQuery();
        
        // Vulnerable query
        var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'";
        
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            bool isAdmin = reader.GetInt32(3) == 1;
            result = $"Login successful! Welcome, {username}. You are {(isAdmin ? "an admin" : "a regular user")}.";
        }
        else
        {
            result = "Login failed. Invalid username or password.";
        }
    }
    catch (Exception ex)
    {
        // Returning error messages is also a vulnerability
        result = $"Error: {ex.Message}";
    }
    
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Login Result</title></head><body>");
    html.AppendLine("<h1>Login Result</h1>");
    html.AppendLine($"<p>{result}</p>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// Login form
app.MapGet("/login-form", () =>
{
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Login</title></head><body>");
    html.AppendLine("<h1>Login</h1>");
    html.AppendLine("<form action='/login' method='post'>");
    html.AppendLine("<label for='username'>Username:</label>");
    html.AppendLine("<input type='text' id='username' name='username'><br><br>");
    html.AppendLine("<label for='password'>Password:</label>");
    html.AppendLine("<input type='password' id='password' name='password'><br><br>");
    html.AppendLine("<input type='submit' value='Login'>");
    html.AppendLine("</form>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

#endregion

#region XSS Vulnerabilities

// Reflected XSS vulnerability
app.MapGet("/greet", (string name) =>
{
    // Vulnerable code - unescaped output
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Greeting</title></head><body>");
    html.AppendLine("<h1>Hello!</h1>");
    // Directly inserting user input into the page
    html.AppendLine($"<p>Welcome, {name}!</p>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// Stored XSS vulnerability
app.MapGet("/comments", () =>
{
    // For demo purposes, we'll use static comments
    var comments = new List<string>
    {
        "Great website!",
        "I love this content.",
        "<script>alert('This is a stored XSS attack!');</script>",
        "Very informative."
    };
    
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Comments</title></head><body>");
    html.AppendLine("<h1>Comments</h1>");
    html.AppendLine("<ul>");
    
    foreach (var comment in comments)
    {
        // Vulnerable code - unescaped output
        html.AppendLine($"<li>{comment}</li>");
    }
    
    html.AppendLine("</ul>");
    html.AppendLine("<form action='/add-comment' method='post'>");
    html.AppendLine("<input type='text' name='comment' placeholder='Add a comment'>");
    html.AppendLine("<input type='submit' value='Submit'>");
    html.AppendLine("</form>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// Add a comment (for XSS demo)
app.MapPost("/add-comment", async (HttpContext context) =>
{
    string comment = "";
    
    if (context.Request.HasFormContentType)
    {
        var form = await context.Request.ReadFormAsync();
        comment = form["comment"];
    }
    
    // In a real app, this would save to a database
    // For this demo, we just redirect back to the comments page
    
    return Results.Redirect("/comments");
});

#endregion

#region XML Injection Vulnerabilities

// XXE vulnerability
app.MapPost("/process-xml", async (HttpContext context) =>
{
    var result = "";
    var xmlString = await new StreamReader(context.Request.Body).ReadToEndAsync();
    
    try
    {
        // Vulnerable code - unsafe XML parsing
        var xmlDoc = new XmlDocument();
        // Disable DTD processing and external entities to prevent XXE attacks in production
        // But for our vulnerable test server, we'll leave it enabled
        xmlDoc.XmlResolver = new XmlUrlResolver();
        xmlDoc.LoadXml(xmlString);
        
        var root = xmlDoc.DocumentElement;
        if (root != null)
        {
            result = $"Successfully processed XML with root element: {root.Name}";
            
            var dataNode = root.SelectSingleNode("//data");
            if (dataNode != null)
            {
                result += $"<br>Data content: {dataNode.InnerText}";
            }
        }
    }
    catch (Exception ex)
    {
        // Returning error messages is also a vulnerability
        result = $"Error processing XML: {ex.Message}";
    }
    
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>XML Processing Result</title></head><body>");
    html.AppendLine("<h1>XML Processing Result</h1>");
    html.AppendLine($"<p>{result}</p>");
    html.AppendLine("<a href='/xml-form'>Try again</a>");
    html.AppendLine("<br>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// Form for XML submission
app.MapGet("/xml-form", () =>
{
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>XML Submission</title></head><body>");
    html.AppendLine("<h1>Submit XML</h1>");
    html.AppendLine("<form action='/process-xml' method='post'>");
    html.AppendLine("<textarea name='xml' rows='10' cols='50'><?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n  <data>Your data here</data>\n</root></textarea>");
    html.AppendLine("<br>");
    html.AppendLine("<input type='submit' value='Process XML'>");
    html.AppendLine("</form>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

#endregion

#region JSON Injection Vulnerabilities

// JSON Injection vulnerability
app.MapPost("/process-json", async (HttpContext context) =>
{
    var result = "";
    var jsonString = await new StreamReader(context.Request.Body).ReadToEndAsync();
    
    try
    {
        // Vulnerable code - unsafe deserialization
        var jsonSettings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All  // This is vulnerable to JSON deserialization attacks
        };
        
        var data = JsonConvert.DeserializeObject<dynamic>(jsonString, jsonSettings);
        result = $"Successfully processed JSON. Received value: {data?.value ?? "none"}";
    }
    catch (Exception ex)
    {
        // Returning error messages is also a vulnerability
        result = $"Error processing JSON: {ex.Message}";
    }
    
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>JSON Processing Result</title></head><body>");
    html.AppendLine("<h1>JSON Processing Result</h1>");
    html.AppendLine($"<p>{result}</p>");
    html.AppendLine("<a href='/json-form'>Try again</a>");
    html.AppendLine("<br>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// Form for JSON submission
app.MapGet("/json-form", () =>
{
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>JSON Submission</title></head><body>");
    html.AppendLine("<h1>Submit JSON</h1>");
    html.AppendLine("<form action='/process-json' method='post'>");
    html.AppendLine("<textarea name='json' rows='10' cols='50'>{\"value\": \"test\"}</textarea>");
    html.AppendLine("<br>");
    html.AppendLine("<input type='submit' value='Process JSON'>");
    html.AppendLine("</form>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

#endregion

#region Command Injection Vulnerabilities

// Command Injection vulnerability
app.MapGet("/ping", (string host) =>
{
    var result = "";
    
    try
    {
        // Vulnerable code - executing commands with user input
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c ping -n 3 {host}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            }
        };
        
        process.Start();
        result = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
    }
    catch (Exception ex)
    {
        // Returning error messages is also a vulnerability
        result = $"Error: {ex.Message}";
    }
    
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Ping Result</title></head><body>");
    html.AppendLine("<h1>Ping Result</h1>");
    html.AppendLine($"<p>Host: {host}</p>");
    html.AppendLine("<pre>");
    html.AppendLine(result);
    html.AppendLine("</pre>");
    html.AppendLine("<a href='/ping-form'>Try another host</a>");
    html.AppendLine("<br>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

// Form for ping
app.MapGet("/ping-form", () =>
{
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Ping Tool</title></head><body>");
    html.AppendLine("<h1>Ping Tool</h1>");
    html.AppendLine("<form action='/ping' method='get'>");
    html.AppendLine("<input type='text' name='host' placeholder='Enter hostname or IP'>");
    html.AppendLine("<input type='submit' value='Ping'>");
    html.AppendLine("</form>");
    html.AppendLine("<a href='/'>Back to Home</a>");
    html.AppendLine("</body></html>");
    
    return Results.Content(html.ToString(), "text/html");
});

#endregion

// Run the app with a specific port
app.Run("http://localhost:5000");

// Helper method to generate the home page
string GetHomePage()
{
    var html = new StringBuilder();
    html.AppendLine("<html><head><title>Vulnerable Test Server</title></head><body>");
    html.AppendLine("<h1>Vulnerable Test Server</h1>");
    html.AppendLine("<p>This server contains intentional vulnerabilities for testing the SentinelVulnScan project. DO NOT USE IN PRODUCTION!</p>");
    
    html.AppendLine("<h2>SQL Injection Vulnerabilities</h2>");
    html.AppendLine("<ul>");
    html.AppendLine("<li><a href='/search?q=phone'>Search Products</a> - Try using: <code>' OR '1'='1</code></li>");
    html.AppendLine("<li><a href='/login-form'>Login Form</a> - Try using: <code>admin' --</code> as username</li>");
    html.AppendLine("</ul>");
    
    html.AppendLine("<h2>XSS Vulnerabilities</h2>");
    html.AppendLine("<ul>");
    html.AppendLine("<li><a href='/greet?name=User'>Greeting Page</a> - Try using: <code><script>alert('XSS')</script></code></li>");
    html.AppendLine("<li><a href='/comments'>Comments Page</a> - Contains stored XSS</li>");
    html.AppendLine("</ul>");
    
    html.AppendLine("<h2>XML Injection Vulnerabilities</h2>");
    html.AppendLine("<ul>");
    html.AppendLine("<li><a href='/xml-form'>XML Processing</a> - Try XXE attacks</li>");
    html.AppendLine("</ul>");
    
    html.AppendLine("<h2>JSON Injection Vulnerabilities</h2>");
    html.AppendLine("<ul>");
    html.AppendLine("<li><a href='/json-form'>JSON Processing</a> - Try deserialization attacks</li>");
    html.AppendLine("</ul>");
    
    html.AppendLine("<h2>Command Injection Vulnerabilities</h2>");
    html.AppendLine("<ul>");
    html.AppendLine("<li><a href='/ping-form'>Ping Tool</a> - Try using: <code>127.0.0.1 & ipconfig</code></li>");
    html.AppendLine("</ul>");
    
    html.AppendLine("</body></html>");
    return html.ToString();
}
