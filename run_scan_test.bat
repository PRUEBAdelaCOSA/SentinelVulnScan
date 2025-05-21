@echo off
echo Starting SentinelVulnScan Test Environment

echo.
echo [1/2] Starting VulnerableTestServer...
start "VulnerableTestServer" cmd /c "cd /d d:\Coding\VSCodeProject\SentinelVulnScan\VulnerableTestServer && dotnet run"

echo.
echo Waiting for server to start...
timeout /t 5 /nobreak

echo.
echo [2/2] Running SentinelVulnScan against the vulnerable server...
echo.
cd /d d:\Coding\VSCodeProject\SentinelVulnScan\src\SentinelVulnScan
dotnet run --test-local

echo.
echo Test completed. The vulnerable server is still running.
echo Press any key to close the vulnerable server or close its window manually.
pause >nul
taskkill /FI "WINDOWTITLE eq VulnerableTestServer*" /F
