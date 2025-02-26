using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Timers;
using InfluxDB.Client;
using InfluxDB.Client.Api.Domain;
using InfluxDB.Client.Writes;
using System.Security.Cryptography.X509Certificates;

namespace TrackerAppService 
{ 


    public partial class TrackerAppService : ServiceBase
    {
        private System.Timers.Timer timer, timer1min;
        private Dictionary<string, TimeSpan> appUsedPerDay = new Dictionary<string, TimeSpan>();
        private Dictionary<string, TimeSpan[]> appUsageLimits = new Dictionary<string, TimeSpan[]>();
        private HashSet<string> warnedApps = new HashSet<string>();
        private HashSet<string> trackedApps = new HashSet<string>();
        private string registryPath = "SOFTWARE\\TrackerAppService";
        private DateTime lastResetDate = DateTime.Now.Date;

        string logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsage.log");

        public TrackerAppService()
        {
            InitializeComponent();
            
        }

        private bool InfluxDBConfigOk()
        {
            return (!string.IsNullOrEmpty(Properties.Settings.Default.influxUrl)
                && !string.IsNullOrEmpty(Properties.Settings.Default.influxToken)
                && !string.IsNullOrEmpty(Properties.Settings.Default.influxOrg)
                && !string.IsNullOrEmpty(Properties.Settings.Default.influxBucket));
        }

        private void SendDataToInfluxDB()
        {
            if (!InfluxDBConfigOk())
            {
                return;
            }

            try
            {
                X509Certificate2 x509Certificate2 = null;

                if (!string.IsNullOrEmpty(Properties.Settings.Default.influxCertKeyFileName))
                {
                    string influxCertKeyFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, Properties.Settings.Default.influxCertKeyFileName);
                    if (System.IO.File.Exists(influxCertKeyFilePath))
                    {
                        string influxCertKeyPass = string.IsNullOrEmpty(Properties.Settings.Default.influxCertKeyPass) ? "" : Properties.Settings.Default.influxCertKeyPass;

                        x509Certificate2 = new X509Certificate2(influxCertKeyFilePath, influxCertKeyPass, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet); //"C:\\Temp\\cert.pfx"
                    }
                }

                var options = new InfluxDBClientOptions(Properties.Settings.Default.influxUrl)
                {
                    Token = Properties.Settings.Default.influxToken,
                    Org = Properties.Settings.Default.influxOrg,
                    Bucket = Properties.Settings.Default.influxBucket,
                    ClientCertificates = x509Certificate2 != null ? new X509CertificateCollection() { x509Certificate2 } : new X509CertificateCollection() { }
                };

                using (var client = new InfluxDBClient(options)) // Properties.Settings.Default.influxUrl, Properties.Settings.Default.influxToken))
                {
                    var connectable = client.PingAsync().Result;

                    if (!connectable)
                    {
                        throw new Exception("InfluxDBClient not connectable");
                    }

                    using (var writeApi = client.GetWriteApi())
                    {
                        DateTime now = DateTime.Now;
                        int dow = (int)now.DayOfWeek;

                        List<PointData> lpd = new List<PointData>();

                        foreach (var entry in appUsageLimits)
                        {
                            var point = PointData.Measurement("tracker-app")
                                .Tag("host", Environment.MachineName)
                                .Tag("application", entry.Key)
                                .Field("run-time-minutes", appUsedPerDay.ContainsKey(entry.Key)? appUsedPerDay[entry.Key].TotalMinutes : 0)
                                .Field("limit-time-minutes", entry.Value[dow].TotalMinutes)
                                .Timestamp(DateTime.UtcNow, WritePrecision.S);

                            lpd.Add(point);
                        }

                        writeApi.WritePoints(lpd); //, Properties.Settings.Default.influxBucket, Properties.Settings.Default.influxOrg);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!EventLog.SourceExists("TrackerAppService"))
                {
                    EventLog.CreateEventSource("TrackerAppService", "Application");
                }
                EventLog.WriteEntry("TrackerAppService", $"Exception: {ex.Message}", EventLogEntryType.Error);
            }
            
        }

        protected override void OnStart(string[] args)
        {
            Properties.Settings.Default.Save();

            LoadTrackedApps();
            LoadUsageFromRegistry();

            timer = new System.Timers.Timer(10000); // Logs every 10 seconds
            timer.Elapsed += TimerElapsed;
            timer.Start();

            if (InfluxDBConfigOk())
            {
                timer1min = new System.Timers.Timer(60000); // Logs every 1 min
                timer1min.Elapsed += Timer1minElapsed;
                timer1min.Start();
            }

            DateTime now = DateTime.Now;
            string logEntry = $"{now}: TrackerAppService started";
            System.IO.File.AppendAllText(logFilePath, Environment.NewLine + logEntry);

            SummarizeUsage();
        }

        private void LoadTrackedApps()
        {
            appUsageLimits.Clear();

            foreach (var line in Properties.Settings.Default.appUsageLimits)
            {
                var parts = line.Split(',');

                string appName = parts[0].Trim();
                trackedApps.Add(appName);

                TimeSpan[] ts = new TimeSpan[7];

                for (int idx=1; idx < parts.Length; idx++)
                {
                    if (TimeSpan.TryParse(parts[idx].Trim(), out TimeSpan limit))
                    {
                        ts.SetValue(limit, idx-1);// = limit;
                    }
                    else
                    {
                        ts.SetValue(TimeSpan.FromHours(1), idx-1); //= TimeSpan.FromHours(1); // Default 1 hour
                    }
                }

                appUsageLimits.Add(appName, ts);

            }

        }

        private void LoadUsageFromRegistry()
        {
            appUsedPerDay.Clear();

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryPath))
            {
                if (key != null)
                {
                    foreach (string appName in key.GetValueNames())
                    {
                        if (appName == "LastResetDate")
                        {
                            string resetDateValue = key.GetValue(appName) as string;
                            if (!string.IsNullOrEmpty(resetDateValue) && DateTime.TryParse(resetDateValue, out DateTime resetDate))
                            {
                                lastResetDate = resetDate;
                            }
                        }
                        else if (TimeSpan.TryParse(key.GetValue(appName).ToString(), out TimeSpan duration))
                        {
                            appUsedPerDay[appName] = duration;
                        }
                    }
                }
            }
        }

        private void TimerElapsed(object sender, ElapsedEventArgs e)
        {
            ResetUsageIfNewDay();

            HashSet<string> appList = new HashSet<string>();

            Process[] processList = Process.GetProcesses();

            foreach (Process process in processList)
            {
                try
                {
                    //Console.WriteLine($"PID: {process.Id}, Name: {process.ProcessName}");

                    if (!string.IsNullOrEmpty(process.ProcessName) 
                     && trackedApps.Contains(process.ProcessName) 
                     && !appList.Contains(process.ProcessName))
                    {
                        appList.Add(process.ProcessName);

                        LogUsage(process.ProcessName);
                        CheckUsageLimit(process.ProcessName);
                    }
                }
                catch (Exception ex)
                {
                    if (!EventLog.SourceExists("TrackerAppService"))
                    {
                        EventLog.CreateEventSource("TrackerAppService", "Application");
                    }
                    EventLog.WriteEntry("TrackerAppService", $"Process running: {process.ProcessName} (Exception: {ex.Message})", EventLogEntryType.Error);
                }
            }
            
        }

        private void Timer1minElapsed(object sender, ElapsedEventArgs e)
        {
            SendDataToInfluxDB();
        }

        private void ResetUsageIfNewDay()
        {
            if (DateTime.Now.Date > lastResetDate)
            {
                List<string> keys = new List<string>(appUsedPerDay.Keys);

                foreach (string key in keys)
                {
                    appUsedPerDay[key] = TimeSpan.Zero;
                }

                warnedApps.Clear();

                lastResetDate = DateTime.Now.Date;

                SaveUsageToRegistry();
            }
        }


        private void LogUsage(string appTitle)
        {
            TimeSpan duration = TimeSpan.Zero;
            DateTime now = DateTime.Now;

            if (!appUsedPerDay.ContainsKey(appTitle))
            {
                appUsedPerDay[appTitle] = TimeSpan.Zero;
            }
            else
            {
                appUsedPerDay[appTitle] += TimeSpan.FromSeconds(10); //+10 sec
            }

            int dow = (int)now.DayOfWeek; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 
            TimeSpan appLimit = (TimeSpan)appUsageLimits[appTitle].GetValue(dow); 
            TimeSpan remainingTime = appLimit - appUsedPerDay[appTitle];

            string signn = remainingTime < TimeSpan.Zero ? "-" : "";

            string logEntry = $"{now}: used:{appUsedPerDay[appTitle].ToString("hh\\:mm\\:ss")}, remains:{signn}{remainingTime.ToString("hh\\:mm\\:ss")}, {appTitle}";
            System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }

        private void CheckUsageLimit(string appTitle)
        {
            if (appUsedPerDay.ContainsKey(appTitle))
            {
                DateTime now = DateTime.Now;
                int dow = (int)now.DayOfWeek; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 
                TimeSpan appLimit = (TimeSpan)appUsageLimits[appTitle].GetValue(dow);

                TimeSpan remainingTime = appLimit - appUsedPerDay[appTitle];                

                if (remainingTime <= TimeSpan.Zero)
                {
                    KillApplication(appTitle);
                }
                else if (remainingTime <= TimeSpan.FromMinutes(5) && !warnedApps.Contains(appTitle))
                {
                    ShowWarningDialog(appTitle, remainingTime);
                    warnedApps.Add(appTitle);
                }
            }
        }


        private void ShowWarningDialog(string appTitle, TimeSpan remainingTime)
        {
            string message = $"Warning: Your usage time for {appTitle.ToUpper()} will expire in 5 minutes!";
            string title = $"{appTitle.ToUpper()} Usage Limit";
            //MessageBox.Show(message, "Usage Limit Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);

            // Requires Microsoft.Toolkit.Uwp.Notifications NuGet package version 7.0 or greater
            new ToastContentBuilder()
                .AddArgument("action", "viewConversation")
                .AddArgument("conversationId", 9813)
                .AddText(title)
                .AddText(message)
                .Show(); // Not seeing the Show() method? Make sure you have version 7.0, and if you're using .NET 6 (or later), then your TFM must be net6.0-windows10.0.17763.0 or greater
        }

        private void KillApplication(string appTitle)
        {
            foreach (var process in Process.GetProcessesByName(appTitle))
            {
                process.Kill();

                string message = $"Usage time for {appTitle.ToUpper()} is expired for today!";
                string title = $"{appTitle.ToUpper()} Usage Limit Expired";

                // Requires Microsoft.Toolkit.Uwp.Notifications NuGet package version 7.0 or greater
                new ToastContentBuilder()
                    .AddArgument("action", "viewConversation")
                    .AddArgument("conversationId", 9813)
                    .AddText(title)
                    .AddText(message)
                    .Show(); // Not seeing the Show() method? Make sure you have version 7.0, and if you're using .NET 6 (or later), then your TFM must be net6.0-windows10.0.17763.0 or greater
            }
        }

        protected override void OnStop()
        {
            timer.Stop();
            timer.Dispose();

            if (timer1min != null)
            {
                timer1min.Stop();
                timer1min.Dispose();
            }

            SummarizeUsage();
            SaveUsageToRegistry();

            DateTime now = DateTime.Now;
            string logEntry = $"{now}: TrackerAppService stopped";
            System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }

        private void SummarizeUsage()
        {
            using (StreamWriter writer = new StreamWriter(logFilePath, true))
            {
                writer.WriteLine("\nApplication Usage Summary:");
                foreach (var entry in appUsedPerDay)
                {
                    writer.WriteLine($"{entry.Key}: {entry.Value}");
                }
            }
        }

        private void SaveUsageToRegistry()
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(registryPath))
            {
                if (key != null)
                {
                    foreach (var entry in appUsedPerDay)
                    {
                        key.SetValue(entry.Key, entry.Value.ToString());
                    }

                    key.SetValue("LastResetDate", lastResetDate.ToString("yyyy-MM-dd"));
                }
            }
        }

    }
}
