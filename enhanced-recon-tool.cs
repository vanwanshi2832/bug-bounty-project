using System;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Net.Http;
using System.Collections.Generic;
using System.Text.Json;

namespace EnhancedReconTool
{
    public partial class MainForm : Form
    {
        private readonly HttpClient _httpClient;
        private Dictionary<string, List<string>> _scanResults;
        
        public MainForm()
        {
            InitializeComponent();
            _httpClient = new HttpClient();
            _scanResults = new Dictionary<string, List<string>>();
            InitializeControls();
        }

        private void InitializeControls()
        {
            // Create tabbed interface for different scan categories
            tabControl = new TabControl();
            tabControl.Dock = DockStyle.Fill;

            // Add scan category tabs
            AddScanTab("Security Scan", new[] {
                "API Endpoints",
                "Open Ports",
                "SSL/TLS Analysis",
                "Security Headers",
                "WAF Detection"
            });

            AddScanTab("Content Discovery", new[] {
                "Directory Enumeration",
                "Hidden Files",
                "Backup Files",
                "Configuration Files",
                "Source Code Leaks"
            });

            AddScanTab("Cloud Resources", new[] {
                "AWS Resources",
                "Azure Resources",
                "GCP Resources",
                "Digital Ocean Spaces",
                "Cloud Storage Misconfigs"
            });

            // Add results panel
            resultsPanel = new Panel();
            resultsPanel.Dock = DockStyle.Right;
            resultsPanel.Width = 400;
            
            // Add export options
            AddExportButtons();
        }

        private async Task PerformScan(string domain, string scanType)
        {
            try
            {
                UpdateStatus($"Scanning {domain} for {scanType}...");

                switch (scanType.ToLower())
                {
                    case "api endpoints":
                        await ScanApiEndpoints(domain);
                        break;
                    
                    case "security headers":
                        await AnalyzeSecurityHeaders(domain);
                        break;

                    case "cloud resources":
                        await ScanCloudResources(domain);
                        break;

                    // Add more scan types
                }

                SaveResults(domain, scanType);
            }
            catch (Exception ex)
            {
                LogError($"Error scanning {domain}: {ex.Message}");
            }
        }

        private async Task ScanApiEndpoints(string domain)
        {
            // Common API patterns to check
            var patterns = new[] {
                "/api/",
                "/v1/",
                "/v2/",
                "/swagger/",
                "/graphql"
            };

            foreach (var pattern in patterns)
            {
                var url = $"https://{domain}{pattern}";
                try
                {
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        AddResult("API Endpoints", url);
                    }
                }
                catch { /* Continue scanning */ }
            }
        }

        private async Task AnalyzeSecurityHeaders(string domain)
        {
            var headers = new[] {
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection"
            };

            var url = $"https://{domain}";
            var response = await _httpClient.GetAsync(url);
            
            foreach (var header in headers)
            {
                if (response.Headers.Contains(header))
                {
                    AddResult("Security Headers", $"{header}: {response.Headers.GetValues(header)}");
                }
                else
                {
                    AddResult("Missing Headers", header);
                }
            }
        }

        private async Task ScanCloudResources(string domain)
        {
            // Check common cloud storage patterns
            var patterns = new[] {
                $"https://{domain}.s3.amazonaws.com",
                $"https://{domain}.blob.core.windows.net",
                $"https://storage.googleapis.com/{domain}",
                $"https://{domain}.digitaloceanspaces.com"
            };

            foreach (var url in patterns)
            {
                try
                {
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        AddResult("Cloud Storage", url);
                    }
                }
                catch { /* Continue scanning */ }
            }
        }

        private void ExportResults(string format)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var filename = $"recon_results_{timestamp}.{format}";

            switch (format)
            {
                case "json":
                    File.WriteAllText(filename, JsonSerializer.Serialize(_scanResults));
                    break;
                    
                case "csv":
                    using (var writer = new StreamWriter(filename))
                    {
                        foreach (var category in _scanResults)
                        {
                            foreach (var result in category.Value)
                            {
                                writer.WriteLine($"{category.Key},{result}");
                            }
                        }
                    }
                    break;
            }
        }

        private void AddResult(string category, string result)
        {
            if (!_scanResults.ContainsKey(category))
            {
                _scanResults[category] = new List<string>();
            }
            _scanResults[category].Add(result);
            UpdateResultsDisplay();
        }
    }
}
