using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Forms;
using InfluxDB.Client;
using InfluxDB.Client.Api.Domain;
using InfluxDB.Client.Writes;

namespace TrackerAppService
{
    public partial class TrackerAppService : ServiceBase
    {
        private System.Timers.Timer timer;
        //private string logFilePath = "C:\\Temp\\AppUsage.log";
        //private string settingsFilePath = "C:\\Temp\\TrackedApps.ini";
        private Dictionary<string, TimeSpan> appUsage = new Dictionary<string, TimeSpan>();
        private Dictionary<string, TimeSpan[]> appUsageLimits = new Dictionary<string, TimeSpan[]>();
        private HashSet<string> warnedApps = new HashSet<string>();
        private string lastApp = null;
        private DateTime lastStartTime;
        private HashSet<string> trackedApps = new HashSet<string>();
        private string registryPath = "SOFTWARE\\TrackerAppService";
        private DateTime lastResetDate = DateTime.Now.Date;
        //public static IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        //string appFolder = AppDomain.CurrentDomain.BaseDirectory;
        string logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsage.log");

        public TrackerAppService()
        {
            InitializeComponent();
            
        }

        private void SendDataToInfluxDB(HashSet<string> appList)
        {
            if (   string.IsNullOrEmpty(Properties.Settings.Default.influxUrl) 
                || string.IsNullOrEmpty(Properties.Settings.Default.influxToken) 
                || string.IsNullOrEmpty(Properties.Settings.Default.influxOrg) 
                || string.IsNullOrEmpty(Properties.Settings.Default.influxBucket))
            {
                return;
            }                

            try
            {
                using (var client = new InfluxDBClient(Properties.Settings.Default.influxUrl, Properties.Settings.Default.influxToken))
                {
                    using (var writeApi = client.GetWriteApi())
                    {
                        List<PointData> lpd = new List<PointData>();

                        foreach (var entry in appList)
                        {
                            var point = PointData.Measurement("tracker-app")
                                .Tag("application", entry)
                                .Field("duration_seconds", 1)
                                .Timestamp(DateTime.UtcNow, WritePrecision.S);

                            lpd.Add(point);
                        }

                        writeApi.WritePoints(lpd, Properties.Settings.Default.influxBucket, Properties.Settings.Default.influxOrg);
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
            LoadLastResetDateFromRegistry();

            timer = new System.Timers.Timer(10000); // Logs every 10 seconds
            timer.Elapsed += TimerElapsed;
            timer.Start();
            lastStartTime = DateTime.Now;

            
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

            /*
            if (System.IO.File.Exists(settingsFilePath))
            {
                trackedApps.Clear();

                foreach (var line in System.IO.File.ReadAllLines(settingsFilePath))
                {
                    var parts = line.Split(',');
                    if (parts.Length >= 1)
                    {
                        string appName = parts[0].Trim();
                        trackedApps.Add(appName);

                        if (parts.Length > 1 && TimeSpan.TryParse(parts[1].Trim(), out TimeSpan limit))
                        {
                            appUsageLimits[appName] = limit;
                        }
                        else
                        {
                            appUsageLimits[appName] = TimeSpan.FromHours(1); // Default 1 hour
                        }
                    }
                }
            }
            else
            { 
                System.IO.File.Create(settingsFilePath).Dispose();
            }
            */
        }

        private void LoadUsageFromRegistry()
        {
            appUsage.Clear();

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryPath))
            {
                if (key != null)
                {
                    foreach (string appName in key.GetValueNames())
                    {
                        if (TimeSpan.TryParse(key.GetValue(appName).ToString(), out TimeSpan duration))
                        {
                            appUsage[appName] = duration;
                        }
                    }
                }
            }
        }

        private void LoadLastResetDateFromRegistry()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryPath))
            {
                if (key != null)
                {
                    string resetDateValue = key.GetValue("LastResetDate") as string;
                    if (!string.IsNullOrEmpty(resetDateValue) && DateTime.TryParse(resetDateValue, out DateTime resetDate))
                    {
                        lastResetDate = resetDate;
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

            if (appList.Count() > 0)
            {
                SendDataToInfluxDB(appList);
            }
            
        }

        private void ResetUsageIfNewDay()
        {
            if (DateTime.Now.Date > lastResetDate)
            {
                List<string> keys = new List<string>(appUsage.Keys);

                foreach (string key in keys)
                {
                    appUsage[key] = TimeSpan.Zero;
                }

                warnedApps.Clear();

                lastResetDate = DateTime.Now.Date;

                SaveLastResetDateToRegistry();
            }
        }


        private void LogUsage(string appTitle)
        {
            TimeSpan duration = TimeSpan.Zero;
            DateTime now = DateTime.Now;
            if (lastApp != null && trackedApps.Contains(lastApp))
            {
                duration = now - lastStartTime;
                if (!appUsage.ContainsKey(lastApp))
                {
                    appUsage[lastApp] = TimeSpan.Zero;
                }
                appUsage[lastApp] += duration;
            }

            lastApp = appTitle;
            lastStartTime = now;

            int dow = (int)now.DayOfWeek; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 
            TimeSpan appLimit = (TimeSpan)appUsageLimits[appTitle].GetValue(dow); 
            TimeSpan remainingTime = appLimit - appUsage[appTitle];

            string signn = remainingTime < TimeSpan.Zero ? "-" : "";

            string logEntry = $"{now}: used:{appUsage[appTitle].ToString("hh\\:mm\\:ss")}, remains:{signn}{remainingTime.ToString("hh\\:mm\\:ss")}, {appTitle}";
            System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }

        private void CheckUsageLimit(string appTitle)
        {
            if (appUsage.ContainsKey(appTitle))
            {
                DateTime now = DateTime.Now;
                int dow = (int)now.DayOfWeek; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 
                TimeSpan appLimit = (TimeSpan)appUsageLimits[appTitle].GetValue(dow);

                TimeSpan remainingTime = appLimit - appUsage[appTitle];                

                if (appUsage[appTitle] >= appLimit)
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
            SummarizeUsage();
            SaveUsageToRegistry();
            SaveLastResetDateToRegistry();
        }

        private void SummarizeUsage()
        {
            using (StreamWriter writer = new StreamWriter(logFilePath, true))
            {
                writer.WriteLine("\nApplication Usage Summary:");
                foreach (var entry in appUsage)
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
                    foreach (var entry in appUsage)
                    {
                        key.SetValue(entry.Key, entry.Value.ToString());
                    }
                }
            }
        }

        private void SaveLastResetDateToRegistry()
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(registryPath))
            {
                if (key != null)
                {
                    key.SetValue("LastResetDate", lastResetDate.ToString("yyyy-MM-dd"));
                }
            }
        }
    }
}
