using InfluxDB.Client.Api.Domain;
//using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reactive;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Remoting.Contexts;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System.Web.Routing;
using System.Web.UI.WebControls;
using System.Windows.Forms;
using System.Xml.Linq;
using TrackerAppService.Properties;
using WatsonWebserver.Core;
using Windows.Security.Cryptography.Certificates;
using Windows.Services.Maps;
using Windows.UI;
using Windows.UI.ApplicationSettings;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using static System.Net.WebRequestMethods;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrayNotify;
using NetFwTypeLib;

namespace TrackerAppService
{
    class FirewallHelper
    {
        public static void OpenPort(int port, string name, NET_FW_IP_PROTOCOL_ protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP)
        {
            Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(type);

            // Check if rule already exists
            foreach (INetFwRule rule in firewallPolicy.Rules)
            {
                if (rule.Name == name)
                {
                    return; // Rule already exists
                }
            }

            INetFwRule newRule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

            newRule.ApplicationName = Process.GetCurrentProcess().MainModule.FileName;
            newRule.Name = name;
            newRule.Description = $"Allow inbound {protocol} traffic on port {port}";
            newRule.Protocol = (int)protocol;
            newRule.LocalPorts = port.ToString();
            newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            newRule.Enabled = true;
            newRule.Grouping = "@firewallapi.dll,-23255";
            newRule.Profiles = (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
            newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;

            firewallPolicy.Rules.Add(newRule);

            EventLog.WriteEntry("TrackerAppService", $"Firewal rule {name} added to list", EventLogEntryType.Information);
        }
    }


    public class SettingsHTTP
    {
        public bool Enabled { get; set; } = false;
        public string WebUserName { get; set; } = "";
        [JsonInclude]
        private byte[] WebPassCRT { get; set; } = new byte[10];
        public string CertName { get; set; } = "";
        [JsonInclude]
        private byte[] CertPassCRT { get; set; } = new byte[10];
        [JsonInclude]
        private byte[] EntrCRT { get; set; } = new byte[20];
        public int Port { get; set; } = 8080;
        public int PortHTTPS { get; set; } = 8443;
        public HashSet<string> NotifyRemoteAppList { get; set; } = new HashSet<string>();

        public SettingsHTTP()
        {  

            // Generate additional entropy (will be used as the Initialization vector)
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(EntrCRT);
            }
        }

        [JsonIgnore]
        public string WebPass {
            get {
                string ret = "";

                try
                {
                    byte[] plaintext = ProtectedData.Unprotect(WebPassCRT, EntrCRT, DataProtectionScope.LocalMachine);

                    ret = Encoding.UTF8.GetString(plaintext);
                }
                catch { }

                return ret;
            }
            set
            {
                try
                {
                    WebPassCRT = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), EntrCRT, DataProtectionScope.LocalMachine);
                }
                catch { }

            }
        }

        [JsonIgnore]
        public string CertPass {
            get
            {
                string ret = "";

                try
                {
                    byte[] plaintext = ProtectedData.Unprotect(CertPassCRT, EntrCRT, DataProtectionScope.LocalMachine);

                    ret = Encoding.UTF8.GetString(plaintext);
                }
                catch { }

                return ret;
            }
            set
            {
                try
                {
                    CertPassCRT = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), EntrCRT, DataProtectionScope.LocalMachine);
                }
                catch { }

            }
        } 

    }

    public class RemoteApp
    {
        public String Host { get; set; }
        public String Url { get; set; }
        public String Ver { get; set; }
        public DateTime UpdateDT { get; set; }
    }


    class HttpServer
    {

        static public Dictionary<string, RemoteApp> remoteAppDict = new Dictionary<string, RemoteApp>();

        private static string appSettingsHTTPFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppSettingsHTTP.json");
        private static SettingsHTTP settingsHTTP = null;

        static private System.Timers.Timer timer1min;

        static private WebserverBase server = null;
        static private WebserverBase serverRedirect = null;
        //public static HttpListener listener = null;

        static private TrackerAppService appService;


        private static void Timer1minElapsed(object sender, ElapsedEventArgs e)
        {

            if (settingsHTTP == null 
            || (settingsHTTP != null && settingsHTTP.NotifyRemoteAppList.Count == 0))
            {
                return;
            }

            string hosturl = $"http://{GetLocalIPAddress()}:{settingsHTTP.Port}";

            if (server != null && server.Settings.Ssl.Enable)
            {
                string cn = server.Settings.Ssl.SslCertificate.Subject;
                string host = GetLocalIPAddress().Replace(".", "-") + "." + cn.Remove(0, 3);
                hosturl = $"https://{host}:{settingsHTTP.PortHTTPS}";
            }

            var rapp = new RemoteApp
            {
                Host = Environment.MachineName,
                Url = hosturl,
                Ver = Assembly.GetEntryAssembly().GetName().Version.ToString(),
                UpdateDT = DateTime.Now
            };

            string jsonData = JsonSerializer.Serialize(rapp, new JsonSerializerOptions { WriteIndented = true });
            var content = new StringContent(jsonData, Encoding.UTF8, "application/json");

            foreach (var item in settingsHTTP.NotifyRemoteAppList)
            {
                new Thread(async () =>
                {
                    var httpClient = new HttpClient
                    {
                        Timeout = TimeSpan.FromSeconds(3)
                    };

                    var url = $"{item}/handle_notify_from_rapp";

                    try
                    {
                        HttpResponseMessage response = await httpClient.PostAsync(url, content);
                        response.EnsureSuccessStatusCode();

                        //string result = await response.Content.ReadAsStringAsync();
                        //Console.WriteLine("Response: " + result);
                    }
                    catch (TaskCanceledException ex)
                    {
                    }
                    catch (Exception ex)
                    {
                        EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                    }
                }).Start();
            }
        }

        private static async Task AuthenticateRequest(HttpContextBase ctx)
        {
            const string Realm = "MyRealm";

            if (ctx.Request.Headers["Authorization"] == null || !IsAuthorized(ctx))
            {                
                string html = $@"<!DOCTYPE html><html>
                <head><title>401 Denied</title></head><body>
                <center><h1>404 access denied</h1></center>
                <hr><center>nginx</center>
                </body></html>";

                // Send 401 Unauthorized response with Digest Auth header
                var nonce = Guid.NewGuid().ToString("N");
                ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                ctx.Response.Headers["WWW-Authenticate"] = $"Digest realm=\"{Realm}\", nonce=\"{nonce}\", algorithm=\"MD5\", qop=\"auth,auth-int\"";
                ctx.Response.ContentType = "text/html";
                await ctx.Response.Send(html);
            }
        }

        public static async Task RunWebServerAsync(CancellationToken ct, TrackerAppService _appService)
        {
            EventLog.WriteEntry("TrackerAppService", $"Run WebServer Async", EventLogEntryType.Information);

            appService = _appService;

            var cclone = Thread.CurrentThread.CurrentCulture.Clone() as CultureInfo;
            cclone.DateTimeFormat = CultureInfo.GetCultureInfo("en-GB").DateTimeFormat;
            cclone.NumberFormat.NumberDecimalSeparator = ".";
            Thread.CurrentThread.CurrentCulture = cclone;

            settingsHTTP = new SettingsHTTP();      

            if (System.IO.File.Exists(appSettingsHTTPFilePath))
            {
                string json = System.IO.File.ReadAllText(appSettingsHTTPFilePath);
                settingsHTTP = JsonSerializer.Deserialize<SettingsHTTP> (json) ?? new SettingsHTTP();
            }
            else
            {
                settingsHTTP.WebUserName = "tmpuser";
                settingsHTTP.WebPass = "tmppass";
                settingsHTTP.Enabled = true;
                string json = JsonSerializer.Serialize(settingsHTTP, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appSettingsHTTPFilePath, json);
            }

            if (!settingsHTTP.Enabled)
            {
                return;
            }

            FirewallHelper.OpenPort(settingsHTTP.Port, $"TrackerAppService_IN{settingsHTTP.Port}", NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP);
            FirewallHelper.OpenPort(settingsHTTP.PortHTTPS, $"TrackerAppService_IN{settingsHTTP.PortHTTPS}", NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP);

            timer1min = new System.Timers.Timer(60000); // Logs every 1 min
            timer1min.Elapsed += Timer1minElapsed;
            timer1min.Start();

            X509Certificate2 cert2 = null;

            if (settingsHTTP.CertName != "")
            {
                try
                {
                    //EventLog.WriteEntry("TrackerAppService", $"Certificate {settingsHTTP.CertName}, cert pass {settingsHTTP.CertPass}", EventLogEntryType.Warning); //debug

                    cert2 = new X509Certificate2(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, settingsHTTP.CertName), settingsHTTP.CertPass);

                    if (DateTime.UtcNow > cert2.NotAfter)
                    {
                        EventLog.WriteEntry("TrackerAppService", $"Certificate {settingsHTTP.CertName} expired and cannot be used (Expiration UTC: {cert2.NotAfter})", EventLogEntryType.Warning);
                        cert2 = null;
                    }
                }
                catch { }
            }

            string host = GetLocalIPAddress();

            WebserverSettings webSettings = new WebserverSettings(host, cert2 != null? settingsHTTP.PortHTTPS : settingsHTTP.Port);
            webSettings.Ssl = new WebserverSettings.SslSettings { SslCertificate = cert2 };
            webSettings.Ssl.Enable = cert2 != null;

            server = new WatsonWebserver.Lite.WebserverLite(webSettings, P404Route);
            server.Routes.AuthenticateRequest = AuthenticateRequest;

            //GET
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.GET, "/", HomeRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.GET, "/settings", SettingsRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.GET, "/remoteapps", RemoteApsRoute);
            
            //POST
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/add_newapp", NewAppRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/app_update", SettingsUpdateRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/add_notify_rapp", RemoteAppAddRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/del_notify_rapp", RemoteAppDelRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/web_config_update", WebConfigUpdateRoute);
            server.Routes.PostAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/influx_config_update", InfluxConfigUpdateRoute);            

            //no auth
            server.Routes.PreAuthentication.Parameter.Add(WatsonWebserver.Core.HttpMethod.POST, "/handle_notify_from_rapp", ReceiveNotifyFromRemoteAppRoute);

            server.Start(ct);

            if (webSettings.Ssl.Enable) //redirect http to https
            {
                serverRedirect = new WatsonWebserver.Lite.WebserverLite(
                    new WebserverSettings {
                        Hostname = host,
                        Port = settingsHTTP.Port
                        }, RedirectToHTTPSRoute);

                serverRedirect.Start();
            }

            while (!ct.IsCancellationRequested)
            {
                Thread.Sleep(1000);
            }

        }

      
        public static async Task SettingsRoute(HttpContextBase ctx)
        {
            
            var appUsageLimitsDict = new Dictionary<string, AppLimitConfig>();

            string trows = "";
            int idx = 0;

            foreach (var appLim in appService.appUsageLimitsDict)
            {
                DateTime dtnow = DateTime.Now;

                trows += $"<tr><td>{appLim.Value.AppName}</td>" +
                    $"<td><input name='TimeEntries[{idx}].FromTime' placeholder='hh.mm' value='{appLim.Value.ActiveFromTime:hh\\:mm}'/></td>" +
                    $"<td><input name='TimeEntries[{idx}].ToTime' placeholder='hh.mm' value='{appLim.Value.ActiveToTime:hh\\:mm}'/></td>";

                foreach (var entry in appLim.Value.UsageLimitsPerDay)
                {
                    trows += $"<td><input name='TimeEntries[{idx}].Limit{entry.Key}' placeholder='hh.mm' value='{entry.Value:hh\\:mm}'/></td>";
                }
                  
                trows += $"<td><div style=' width: 130px;'>" +
                    $"<button type='submit' name='UpdateBtn' value='{idx}' >Update</button>" +
                    $"<button type='submit' name='DeleteBtn' value='{idx}' >Delete</button>" +
                    $"<input type='hidden' name='AppName_{idx}' value='{appLim.Value.AppName}'/>" +
                    $"</div></td>" +
                    $"</tr>";

                idx++;
            }

            string notifyAppRows = "";

            foreach (var item in settingsHTTP.NotifyRemoteAppList)
            {
                notifyAppRows += $"<tr>" +
                    $"<td>{item}</td>" +
                    $"<td><button type='submit' name='NotifyAppDeleteBtn' value='{item}' >Delete</button></td></tr>";
            }

            string html = $@"
            <html>
            <head>
            <style>
            td .bg {{position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                background-color: #8ef;
                z-index: -1;
            }}

            ul {{
              list-style-type: none;
              margin: 0;
              padding: 0;
              overflow: hidden;
            }}

            li {{
              float: left;
            }}

            li a {{
              display: block;
              padding: 8px;
              background-color: #dddddd;
            }}

            p.double {{border - style: double;}}

            table {{font - family: arial, sans-serif;
              border-collapse: collapse;
              width: 90%;  }}

            td, th {{border: 1px solid #dddddd;
              text-align: left;
              padding: 4px;
              position: relative; }}

            td input {{
              text-align: left;
              width: 60px; }}

            tr:nth-child(even) {{background-color: #f8f8f8;}}

            </style>
            </head>
            <body>
                <h2>Tracker app (Host: {Environment.MachineName}, Ver: {Assembly.GetEntryAssembly().GetName().Version})   {DateTime.Now}  {DateTime.Now.DayOfWeek}</h2>
                <h3>Settings</h3>
                <ul>
                  <li><a href='/'>Home</a></li>
                  <li><a href='/settings'>Settings</a></li>
                  <li><a href='/remoteapps'>Remote apps</a></li>
                </ul><p><p>
                <p/><p><b>App usage status ({DateTime.Now:dd.MM.yyyy}):</b> List of applications with information for used time for current day.</p>
                <form method='POST' id='my_form' action='/app_update'>
                <table>
                  <thead>
                    <tr>
                    <th>Application</th>
                    <th>Active from time</th>
                    <th>Active to time</th>
                    <th>Sunday</th>
                    <th>Monday</th>
                    <th>Tuesday</th>
                    <th>Wednesday</th>
                    <th>Thursday</th>
                    <th>Friday</th>
                    <th>Saturday</th>
                    <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>{trows}</tbody>
                </table>
                </form>
                <p><b>Add new application usage limit</b> Enter name of application to limit usage time</p>
              <form action='/add_newapp' method='post'>
                <input name='AppUsagNameNew' placeholder='application name' />
                <input type='submit' value='Add application'>
              </form>

              <br><p><b>Remote apps to notify:</b> List of remote applications to report current app alive status.</p>
              <form method='POST' id='my_form' action='/del_notify_rapp'>
                <table style='width: 500px;'>
                  <thead>
                    <tr>
                    <th>Notify remote app url</th>
                    <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>{notifyAppRows}</tbody>
                </table>
                </form>

              <b>Notify remote apps add:</b> Add remote app url to notify.</p>
              <form action='/add_notify_rapp' method='post'>
                <input name='NotifyAppUrl' placeholder='remote application url' />
                <input type='submit' value='Add remote app'>
              </form>

              <br><p><b>HTTP server settings:</b> Web server configuration.</p>
              <form method='POST' id='my_form' action='/web_config_update'>
                <table style='width: 500px;'>
                  <thead>
                    <tr>
                    <th>Parameter</th>
                    <th>Value</th>
                    </tr>
                  </thead>
                    <tbody>
                    <tr><td>HTTP Enabled</td><td><input name='parmWebEnabled' value='{settingsHTTP.Enabled}' style='width: 150px;'/></td></tr>
                    <tr><td>User name</td><td><input name='parmWebUserName' value='{settingsHTTP.WebUserName}' style='width: 150px;'/></td></tr>
                    <tr><td>User password</td><td><input name='parmWebUserPassw' value='{settingsHTTP.WebPass}' style='width: 150px;'/></td></tr>
                    <tr><td>HTTP Port</td><td><input name='parmWebPort' value='{settingsHTTP.Port}' style='width: 150px;'/></td></tr>
                    <tr><td>HTTPS Port</td><td><input name='parmWebPortHTTPS' value='{settingsHTTP.PortHTTPS}' style='width: 150px;'/></td></tr>
                    <tr><td>Certificate file name</td><td><input name='parmWebCertName' value='{settingsHTTP.CertName}' style='width: 150px;'/></td></tr>
                    <tr><td>Certificate password</td><td><input name='parmWebCertPassw' value='{settingsHTTP.CertPass}' style='width: 150px;'/></td></tr>
                    </tbody>
                </table>
                <input type='submit' value='Save settings'>
                </form>

              <br><p><b>Influx DB settings:</b> Configure inflixDB parameters.</p>
              <form method='POST' id='my_form' action='/influx_config_update'>
                <table style='width: 500px;'>
                  <thead>
                    <tr>
                    <th>Parameter</th>
                    <th>Value</th>
                    </tr>
                  </thead>
                    <tbody>
                    <tr><td>Enabled</td><td><input name='parmInfluxEnabled' value='{appService.influxConfig.Enabled}' style='width: 150px;'/></td></tr>
                    <tr><td>Url</td><td><input name='parmInfluxUrl' value='{appService.influxConfig.Url}' style='width: 150px;'/></td></tr>
                    <tr><td>Org</td><td><input name='parmInfluxOrg' value='{appService.influxConfig.Org}' style='width: 150px;'/></td></tr>
                    <tr><td>Bucket</td><td><input name='parmInfluxBucket' value='{appService.influxConfig.Bucket}' style='width: 150px;'/></td></tr>
                    <tr><td>Token</td><td><input name='parmInfluxToken' value='{appService.influxConfig.Token}' style='width: 150px;'/></td></tr>
                    <tr><td>mTLS Certificate file name</td><td><input name='parmInfluxCertName' value='{appService.influxConfig.CertName}' style='width: 150px;'/></td></tr>
                    <tr><td>mTLS Certificate password</td><td><input name='parmInfluxCertPassw' value='{appService.influxConfig.CertPass}' style='width: 150px;'/></td></tr>
                    </tbody>
                </table>
                <input type='submit' value='Save settings'>
                </form>

            </body>
            </html>";

            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send(html);

        }

        public static async Task HomeRoute(HttpContextBase ctx)
        {
            
            var newDictionary = appService.appUsagePerDay.ToDictionary(entry => entry.Key, entry => entry.Value);

            DateTime dtnow = DateTime.Now;
            string trows = "";
            foreach (var appUsage in newDictionary)
            {
                string tdstyle = "";
                AppLimitConfig appLimit = new AppLimitConfig();
                appLimit.initDefault(appUsage.Key);

                if (appService.appUsageLimitsDict.ContainsKey(appUsage.Key))
                {
                    appLimit = appService.appUsageLimitsDict[appUsage.Key];
                    tdstyle = "style='background-color: lightgreen;'";
                }

                TimeSpan tsWindow = appLimit.ActiveToTime - appLimit.ActiveFromTime;
                TimeSpan tsLimit = appLimit.UsageLimitsPerDay[dtnow.DayOfWeek];

                tsLimit = tsLimit > tsWindow ? tsWindow : tsLimit;

                double usagePct = appUsage.Value.TotalMinutes/tsLimit.TotalMinutes *100;

                TimeSpan timeNow = dtnow - dtnow.Date;
                double fromPct = appLimit.ActiveFromTime > timeNow ? 100 : 0;
                double toPct   = appLimit.ActiveToTime <= timeNow ? 100 : 0;

                trows += $"<tr><td>{appUsage.Key}</td>" +
                    $"<td style='z-index: 1;'><div class='bg' style='width: {usagePct:0.##}%;'></div>{usagePct:0.##}</td>" +
                    $"<td>{appUsage.Value}</td>" +
                    $"<td>{appLimit.UsageLimitsPerDay[dtnow.DayOfWeek]:hh\\:mm} / {tsWindow:hh\\:mm}</td>" +
                    $"<td style='z-index: 1;'><div class='bg' style='background-color: #ff9900; width: {fromPct:0.##}%;'></div> {appLimit.ActiveFromTime:hh\\:mm}</td>" +
                    $"<td style='z-index: 1;'><div class='bg' style='background-color: #ff9900; width: {toPct:0.##}%;'></div> {appLimit.ActiveToTime:hh\\:mm}</td>" +
                    $"<td {tdstyle}>{appService.appUsageLimitsDict.ContainsKey(appUsage.Key)}</td></tr>";
            }

            string html = $@"
            <html>
            <head>
            <style>
            td .bg {{position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                background-color: #8ef;
                z-index: -1;
            }}

            ul {{
              list-style-type: none;
              margin: 0;
              padding: 0;
              overflow: hidden;
            }}

            li {{
              float: left;
            }}

            li a {{
              display: block;
              padding: 8px;
              background-color: #dddddd;
            }}

            p.double {{border - style: double;}}

            table {{font - family: arial, sans-serif;
              border-collapse: collapse;
              width: 90%;  }}

            td, th {{border: 1px solid #dddddd;
              text-align: left;
              padding: 8px;
              position: relative; }}

            tr:nth-child(even) {{background-color: #f8f8f8;}}

            </style>
            </head>
            <body>
                <h2>Tracker app (Host: {Environment.MachineName}, Ver: {Assembly.GetEntryAssembly().GetName().Version})   {DateTime.Now}  {DateTime.Now.DayOfWeek}</h2>
                <h3>Home</h3>
                <ul>
                  <li><a href=""/"">Home</a></li>
                  <li><a href=""/settings"">Settings</a></li>
                  <li><a href='/remoteapps'>Remote apps</a></li>
                </ul><p><p>
                <p><b>App usage status ({appService.lastResetDate:dd.MM.yyyy}):</b> List of applications with information for used time for current day.</p>
                <table>
                  <tr>
                    <th>Application</th>
                    <th>Usage %</th>
                    <th>Usage time</th>
                    <th>Limit (day/from-to)</th>
                    <th>Active from time</th>
                    <th>Active to time</th>
                    <th>App config</th>
                  </tr>{trows}
                </table>
            </body>
            </html>";

            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send(html);
        }

        public static async Task P404Route(HttpContextBase ctx)
        {
            string html = $@"<html>
                <head><title>404 Not Found</title></head>
                <body>
                <center><h1>404 Not Found</h1></center>
                <hr><center>nginx</center>
                </body></html>";

            ctx.Response.StatusCode = (int)HttpStatusCode.NotFound;
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send(html);
        }


        public static async Task RemoteApsRoute(HttpContextBase ctx)
        {
            var dtnow = DateTime.UtcNow;
            string trows = "";

            foreach (var app in remoteAppDict)
            {
                TimeSpan ts = dtnow - app.Value.UpdateDT;

                if (ts.TotalMinutes < 10)
                {
                    trows += $"<tr><td><a href='{app.Key}' target='_blank' rel='noopener noreferrer'>{app.Key}</a></td>" +
                       $"<td>{app.Value.Host}</td>" +
                       $"<td>{app.Value.Ver}</td>" +
                       $"<td>{app.Value.UpdateDT.ToLocalTime()}</td></tr>";
                }
            }

            string html = $@"
            <html>
            <head>
            <style>
            td .bg {{position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                background-color: #8ef;
                z-index: -1;
            }}

            ul {{
              list-style-type: none;
              margin: 0;
              padding: 0;
              overflow: hidden;
            }}

            li {{
              float: left;
            }}

            li a {{
              display: block;
              padding: 8px;
              background-color: #dddddd;
            }}

            p.double {{border - style: double;}}

            table {{font - family: arial, sans-serif;
              border-collapse: collapse;
              width: 90%;  }}

            td, th {{border: 1px solid #dddddd;
              text-align: left;
              padding: 8px;
              position: relative; }}

            tr:nth-child(even) {{background-color: #f8f8f8;}}

            </style>
            </head>
            <body>
                <h2>Tracker app (Host: {Environment.MachineName}, Ver: {Assembly.GetEntryAssembly().GetName().Version})   {DateTime.Now}  {DateTime.Now.DayOfWeek}</h2>
                <h3>Remote apps</h3>
                <ul>
                  <li><a href=""/"">Home</a></li>
                  <li><a href=""/settings"">Settings</a></li>
                  <li><a href='/remoteapps'>Remote apps</a></li>
                </ul><p><p>
                <p><b>Remote apps list currently active:</b>List of applications.</p>
                <table>
                  <tr>
                    <th>Url (new tab)</th>
                    <th>Host</th>
                    <th>Version</th>
                    <th>Last update</th>
                  </tr>{trows}
                </table>
            </body>
            </html>";

            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send(html);
        }

        public static async Task SettingsUpdateRoute(HttpContextBase ctx)
        {
            
            var body = ctx.Request.DataAsString;
            var parsed = System.Web.HttpUtility.ParseQueryString(body);

            string deleteIdx = parsed["DeleteBtn"];
            string updateIdx = parsed["UpdateBtn"];

            if (deleteIdx != "" && deleteIdx != null)
            {
                int idx = -1;

                if (Int32.TryParse(deleteIdx, out idx))
                {
                    string appName = parsed[$"AppName_{idx}"];

                    if (appName != "" && appService.appUsageLimitsDict.ContainsKey(appName))
                    {
                        appService.appUsageLimitsDict.Remove(appName);
                        appService.SaveAppUsageLimitsToFile();
                    }
                } 
            }
            else if (updateIdx != "" && updateIdx != null)
            {
                int idx = -1;

                if (Int32.TryParse(updateIdx, out idx))
                {
                    string appName = parsed[$"AppName_{idx}"];

                    if (appName != "" && appService.appUsageLimitsDict.ContainsKey(appName))
                    {
                        AppLimitConfig origAppCfg = appService.appUsageLimitsDict[appName];
                        AppLimitConfig newAppCfg = new AppLimitConfig(); 

                        var culture = new CultureInfo("en-US");

                        try
                        {
                            newAppCfg.AppName = origAppCfg.AppName;
                            newAppCfg.ActiveFromTime = TimeSpan.Parse(parsed[$"TimeEntries[{idx}].FromTime"], culture);
                            newAppCfg.ActiveToTime = TimeSpan.Parse(parsed[$"TimeEntries[{idx}].ToTime"], culture);
                            newAppCfg.UsageLimitsPerDay = new Dictionary<DayOfWeek, TimeSpan>();

                            foreach (var entry in origAppCfg.UsageLimitsPerDay)
                            {
                                newAppCfg.UsageLimitsPerDay.Add(entry.Key, TimeSpan.Parse(parsed[$"TimeEntries[{idx}].Limit{entry.Key}"], culture));
                            }

                            appService.appUsageLimitsDict[appName] = newAppCfg;

                            appService.SaveAppUsageLimitsToFile();
                        }
                        catch (Exception ex)
                        {
                            EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                        }   
                    }
                }
            }

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", "/settings");
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();
        }

        public static async Task WebConfigUpdateRoute(HttpContextBase ctx)
        {

            var body = ctx.Request.DataAsString;
            var parsed = System.Web.HttpUtility.ParseQueryString(body);

            settingsHTTP.Enabled = bool.Parse(parsed["parmWebEnabled"]);
            settingsHTTP.WebUserName = parsed["parmWebUserName"];
            settingsHTTP.WebPass = parsed["parmWebUserPassw"];
            settingsHTTP.Port = int.Parse(parsed["parmWebPort"]);
            settingsHTTP.PortHTTPS = int.Parse(parsed["parmWebPortHTTPS"]);
            settingsHTTP.CertName = parsed["parmWebCertName"];
            settingsHTTP.CertPass = parsed["parmWebCertPassw"];

            string json = JsonSerializer.Serialize(settingsHTTP, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(appSettingsHTTPFilePath, json);

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", "/settings");
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();

        }

        public static async Task InfluxConfigUpdateRoute(HttpContextBase ctx)
        {
          
            var body = ctx.Request.DataAsString;
            var parsed = System.Web.HttpUtility.ParseQueryString(body);

            appService.influxConfig.Enabled = bool.Parse(parsed["parmInfluxEnabled"]);
            appService.influxConfig.Url = parsed["parmInfluxUrl"];
            appService.influxConfig.Org = parsed["parmInfluxOrg"];
            appService.influxConfig.Bucket = parsed["parmInfluxBucket"];
            appService.influxConfig.Token = parsed["parmInfluxToken"];
            appService.influxConfig.CertName = parsed["parmInfluxCertName"];
            appService.influxConfig.CertPass = parsed["parmInfluxCertPassw"];

            string json = JsonSerializer.Serialize(appService.influxConfig, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(appService.influxConfigFilePath, json);

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", "/settings");
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();

        }


        public static async Task NewAppRoute(HttpContextBase ctx)
        {
            
            var body = ctx.Request.DataAsString; 
            var parsed = System.Web.HttpUtility.ParseQueryString(body);

            string newApp = parsed["AppUsagNameNew"];

            if (newApp != "" && !appService.appUsageLimitsDict.ContainsKey(newApp))
            {
                var appLimitCfg = new AppLimitConfig();

                appLimitCfg.initDefault(newApp);

                appService.appUsageLimitsDict.Add(newApp, appLimitCfg);

                appService.SaveAppUsageLimitsToFile();
            }             

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", "/settings");
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();
        }

        

        public static async Task ReceiveNotifyFromRemoteAppRoute(HttpContextBase ctx)
        {
            
            var body = ctx.Request.DataAsString;
            RemoteApp remapp = null;

            if (body != null && body != "")
            {
                try
                {
                    remapp = JsonSerializer.Deserialize<RemoteApp>(body) ?? new RemoteApp();
                }
                catch { }
                    
            }

            if (remapp != null && remapp.Url != "" && remapp.Url != null)
            {
                if (remoteAppDict.ContainsKey(remapp.Url))
                {
                    remoteAppDict[remapp.Url].UpdateDT = DateTime.UtcNow;
                }
                else
                {
                    remoteAppDict.Add(remapp.Url, remapp);
                }
            }

            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            await ctx.Response.Send();
        }

        

        public static async Task RemoteAppAddRoute(HttpContextBase ctx)
        {
            
            var body = ctx.Request.DataAsString;
            var parsed = System.Web.HttpUtility.ParseQueryString(body);

            string remoteAppUrl = parsed["NotifyAppUrl"];

            if (remoteAppUrl != "" && remoteAppUrl != null  && !settingsHTTP.NotifyRemoteAppList.Contains(remoteAppUrl))
            {
                settingsHTTP.NotifyRemoteAppList.Add(remoteAppUrl);

                string json = JsonSerializer.Serialize(settingsHTTP, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appSettingsHTTPFilePath, json);
            }

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", "/settings");
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();
        }

        public static async Task RemoteAppDelRoute(HttpContextBase ctx)
        {
            
            var body = ctx.Request.DataAsString;
            var parsed = System.Web.HttpUtility.ParseQueryString(body);

            string remoteAppUrl = parsed["NotifyAppDeleteBtn"];

            if (remoteAppUrl != "" && remoteAppUrl != null && settingsHTTP.NotifyRemoteAppList.Contains(remoteAppUrl))
            {
                settingsHTTP.NotifyRemoteAppList.Remove(remoteAppUrl);

                string json = JsonSerializer.Serialize(settingsHTTP, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appSettingsHTTPFilePath, json);
            }

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", "/settings");
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();
        }

        public static async Task RedirectToHTTPSRoute(HttpContextBase ctx)
        {
            string cn = server.Settings.Ssl.SslCertificate.Subject;
            string host = ctx.Request.Destination.Hostname.Replace(".", "-") + "." + cn.Remove(0, 3);
            string url = $"https://{host}:{settingsHTTP.PortHTTPS}{ctx.Request.Url.RawWithoutQuery}";

            ctx.Response.StatusCode = (int)HttpStatusCode.Redirect;
            ctx.Response.Headers.Add("Location", url);
            ctx.Response.ContentType = "text/html";
            await ctx.Response.Send();
        }

        /*
        static Settings2 LoadSettings()
        {
            Settings2 defaultSettings = new Settings2 { Username = "admin", Theme = "light", RefreshInterval = 60 };

            if (!System.IO.File.Exists("settingsPath87687.hbj"))
            {
                defaultSettings = new Settings2 { Username = "admin", Theme = "light", RefreshInterval = 60 };

                
                //System.IO.File.WriteAllText(settingsPath, JsonSerializer.Serialize(defaultSettings, new JsonSerializerOptions { WriteIndented = true }));
            }
            return defaultSettings;
            //var json = System.IO.File.ReadAllText(settingsPath);
            //return JsonSerializer.Deserialize<Settings2>(json);
        }
        */

        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "";
        }

        private static bool IsAuthorized(HttpContextBase ctx) //WatsonWebserver.ServerContext ctx)
        {
            const string Realm = "MyRealm";

            var authHeader = ctx.Request.Headers["Authorization"];

            if (authHeader == null)
            {
                return false;
            }

            if (!authHeader.StartsWith("Digest "))
                return false;

            var authParams = ParseAuthHeader(authHeader.Substring(7));
            if (!authParams.ContainsKey("username") 
            || !authParams.ContainsKey("nonce") 
            || !authParams.ContainsKey("response"))
                return false;

            // Compute HA1 and HA2 for Digest Authentication validation
            var ha1 = ComputeMD5Hash($"{settingsHTTP.WebUserName}:{Realm}:{settingsHTTP.WebPass}");
            var ha2 = ComputeMD5Hash($"{ctx.Request.Method}:{ctx.Request.Url.RawWithoutQuery}"); //AbsolutePath
            var validResponse = ComputeMD5Hash($"{ha1}:{authParams["nonce"]}:{authParams["nc"]}:{authParams["cnonce"]}:{authParams["qop"]}:{ha2}");

            // Check if the response matches
            return string.Equals(authParams["response"], validResponse, StringComparison.OrdinalIgnoreCase);
        }

        // Function to parse the Digest Authorization header
        private static Dictionary<string, string> ParseAuthHeader(string header)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var parts = header.Split(',');

            foreach (var part in parts)
            {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length == 2)
                {
                    var key = kv[0].Trim();
                    var val = kv[1].Trim().Trim('"');
                    dict[key] = val;
                }
            }

            return dict;
        }

        // Function to compute MD5 hash
        private static string ComputeMD5Hash(string input)
        {
            using (var md5 = MD5.Create())
            {
                var inputBytes = Encoding.UTF8.GetBytes(input);
                var hashBytes = md5.ComputeHash(inputBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

    }
}
