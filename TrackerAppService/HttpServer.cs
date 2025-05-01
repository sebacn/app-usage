using InfluxDB.Client.Api.Domain;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using TrackerAppService.Properties;
using Windows.Services.Maps;
using Windows.UI;
using Windows.UI.ApplicationSettings;
using Windows.UI.Xaml.Controls;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrayNotify;

namespace TrackerAppService
{

    public class Settings2
    {
        public string Username { get; set; }
        public string Theme { get; set; }
        public int RefreshInterval { get; set; }
    }


    class HttpServer
    {
        //static string settingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WebSettings.json");
        static string validUsername = Properties.Settings.Default.webUser;
        static string validPassword = Properties.Settings.Default.webPass;


        public static HttpListener listener;
       /// <summary>
       /// public static string url = "http://localhost:8321/";
       /// </summary>
       // public static int pageViews = 0;
        public static int requestCount = 0;
        public static string pageData =
            "<!DOCTYPE>" +
            "<html>" +
            "  <head>" +
            "    <title>HttpListener Example</title>" +
            "  </head>" +
            "  <body>" +
            "    <p>Page Views: {0}</p>" +
            "    <form method=\"post\" action=\"shutdown\">" +
            "      <input type=\"submit\" value=\"Shutdown\" {1}>" +
            "    </form>" +
            "  </body>" +
            "</html>";

        public static async Task RunWebServerAsync(CancellationToken ct, TrackerAppService _appService)
        {
            EventLog.WriteEntry("TrackerAppService", $"Run WebServer Async", EventLogEntryType.Information);

            HttpListener listener = new HttpListener();
            listener.Prefixes.Add($"http://{GetLocalIPAddress()}:{Properties.Settings.Default.webPort}/");
            listener.AuthenticationSchemes = AuthenticationSchemes.Basic;
            //listener.Realm = realm;
            //listener.AuthenticationSchemeSelectorDelegate = context => AuthenticationSchemes.Digest;

            listener.Start();

            EventLog.WriteEntry("TrackerAppService", $"HTTP address: {listener.Prefixes.First()}", EventLogEntryType.Information);

            //Console.WriteLine("Server started at http://localhost:8080/");

            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext context = await listener.GetContextAsync();  //listener.GetContext();

                if (!ValidateUser(context))
                {
                    context.Response.StatusCode = 401;
                    context.Response.Close();
                    continue;
                }

                if (context.Request.HttpMethod == "GET")
                {
                    if (context.Request.Url.AbsolutePath == "/settings")
                    {
                        ServeSettingsPage(context, _appService);
                    }
                    else if (context.Request.Url.AbsolutePath == "/")
                    {
                        ServeInfoPage(context, _appService);
                    }
                    else
                    {
                        context.Response.StatusCode = 404;
                        context.Response.Close();
                        continue;
                    }
                }
                else if (context.Request.HttpMethod == "POST")
                {
                    if (context.Request.Url.AbsolutePath == "/add_newapp")
                    {
                        HandleSettingsNewApp(context, _appService);
                    }
                    else if (context.Request.Url.AbsolutePath == "/app_update")
                    {
                        HandleSettingsUpdate(context, _appService);
                    }
                    else
                    {
                        context.Response.StatusCode = 404;
                        context.Response.Close();
                        continue;
                    }
                }
            }
        }

        static bool ValidateUser(HttpListenerContext context)
        {
            IPrincipal user = context.User;
            if (user?.Identity is HttpListenerBasicIdentity identity)
            {
                return identity.Name == validUsername && identity.Password == validPassword;
            }
            return false;
        }

        static async void ServeSettingsPage(HttpListenerContext context, TrackerAppService _appService)
        {
            var appUsageLimitsDict = new Dictionary<string, AppLimitConfig>();

            string trows = "";
            int idx = 0;

            foreach (var appLim in _appService.appUsageLimitsDict)
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
                <h2>Tracker app {DateTime.Now} ver: {Assembly.GetEntryAssembly().GetName().Version}</h2>
                <ul>
                  <li><a href='/'>Home</a></li>
                  <li><a href='/settings'>Settings</a></li>
                </ul><p><p>
                <p><b>App usage status ({DateTime.Now:dd.MM.yyyy}):</b> List of applications with information for used time for current day.</p>
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
            </body>
            </html>";

            /*
            < form action = '/update_applimit' method = 'post' >
            < button type = 'submit' > Submit </ button >
                </ form >
            */

            byte[] buffer = Encoding.UTF8.GetBytes(html);
            context.Response.ContentType = "text/html";
            context.Response.ContentLength64 = buffer.Length;
            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length); //Write(buffer, 0, buffer.Length);
            context.Response.Close();
        }

        static async void ServeInfoPage(HttpListenerContext context, TrackerAppService _appService)
        {
            /*
            var appUsageLimitsDict = new Dictionary<string, AppLimitConfig>();

            string appUsageLimitsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsageLimits.json");

            if (System.IO.File.Exists(appUsageLimitsFilePath))
            {
                string json = System.IO.File.ReadAllText(appUsageLimitsFilePath);
                appUsageLimitsDict = JsonSerializer.Deserialize<Dictionary<string, AppLimitConfig>>(json) ?? new Dictionary<string, AppLimitConfig>();
            }
            */
            var newDictionary = _appService.appUsagePerDay.ToDictionary(entry => entry.Key, entry => entry.Value);

            DateTime dtnow = DateTime.Now;
            string trows = "";
            foreach (var appUsage in newDictionary)
            {
                string tdstyle = "";
                AppLimitConfig appLimit = new AppLimitConfig();
                appLimit.initDefault(appUsage.Key);

                if (_appService.appUsageLimitsDict.ContainsKey(appUsage.Key))
                {
                    appLimit = _appService.appUsageLimitsDict[appUsage.Key];
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
                    $"<td {tdstyle}>{_appService.appUsageLimitsDict.ContainsKey(appUsage.Key)}</td></tr>";
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
                <ul>
                  <li><a href=""/"">Home</a></li>
                  <li><a href=""/settings"">Settings</a></li>
                </ul><p><p>
                <p><b>App usage status ({_appService.lastResetDate:dd.MM.yyyy}):</b> List of applications with information for used time for current day.</p>
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

            byte[] buffer = Encoding.UTF8.GetBytes(html);
            context.Response.ContentType = "text/html";
            context.Response.ContentLength64 = buffer.Length;
            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length); //Write(buffer, 0, buffer.Length);
            context.Response.Close();
        }

        static void HandleSettingsUpdate(HttpListenerContext context, TrackerAppService _appService)
        {
            using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
            {
                var body = reader.ReadToEnd();
                var parsed = System.Web.HttpUtility.ParseQueryString(body);

                string deleteIdx = parsed["DeleteBtn"];
                string updateIdx = parsed["UpdateBtn"];

                if (deleteIdx != "" && deleteIdx != null)
                {
                    int idx = -1;

                    if (Int32.TryParse(deleteIdx, out idx))
                    {
                        string appName = parsed[$"AppName_{idx}"];

                        if (appName != "" && _appService.appUsageLimitsDict.ContainsKey(appName))
                        {
                            _appService.appUsageLimitsDict.Remove(appName);
                            _appService.SaveAppUsageLimitsToFile();
                        }
                    } 
                }
                else if (updateIdx != "" && updateIdx != null)
                {
                    int idx = -1;

                    if (Int32.TryParse(updateIdx, out idx))
                    {
                        string appName = parsed[$"AppName_{idx}"];

                        if (appName != "" && _appService.appUsageLimitsDict.ContainsKey(appName))
                        {
                            AppLimitConfig origAppCfg = _appService.appUsageLimitsDict[appName];
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

                                _appService.appUsageLimitsDict[appName] = newAppCfg;

                                _appService.SaveAppUsageLimitsToFile();
                            }
                            catch (Exception ex)
                            {
                                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                            }   
                        }
                    }
                }

            }

            context.Response.Redirect("/settings");
            context.Response.Close();
        }

        static void HandleSettingsNewApp(HttpListenerContext context, TrackerAppService _appService)
        {
            using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
            {
                var body = reader.ReadToEnd();
                var parsed = System.Web.HttpUtility.ParseQueryString(body);

                string newApp = parsed["AppUsagNameNew"];

                if (newApp != "" && !_appService.appUsageLimitsDict.ContainsKey(newApp))
                {
                    var appLimitCfg = new AppLimitConfig();

                    appLimitCfg.initDefault(newApp);

                    _appService.appUsageLimitsDict.Add(newApp, appLimitCfg);

                    _appService.SaveAppUsageLimitsToFile();
                } 
            }

            context.Response.Redirect("/settings");
            context.Response.Close();
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

    }
}
