﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Timers;
using InfluxDB.Client;
using InfluxDB.Client.Api.Domain;
using InfluxDB.Client.Writes;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Input;
using System.Windows.Forms;
using System.Linq;

namespace TrackerAppService 
{
 

    public partial class TrackerAppService : ServiceBase
    {

        private System.Timers.Timer timer, timer1min;
        private Dictionary<string, TimeSpan> appUsagePerDay = new Dictionary<string, TimeSpan>();
        private Dictionary<string, TimeSpan[]> appUsageLimits = new Dictionary<string, TimeSpan[]>();
        private HashSet<string> warnedApps = new HashSet<string>();
        private HashSet<string> trackedApps = new HashSet<string>();
        private string registryPath = "SOFTWARE\\TrackerAppService";
        private const string regUsage = "\\usage";
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

        private void SendDataToInfluxDB(DateTime? _dt = null, bool _idle = false)
        {
            if (!InfluxDBConfigOk())
            {
                return;
            }

            DateTime dt = _dt ?? DateTime.UtcNow;

            try
            {

                X509Certificate2 x509Certificate2 = null;

                if (!string.IsNullOrEmpty(Properties.Settings.Default.influxCertKeyFileName))
                {
                    string influxCertKeyFilePath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, Properties.Settings.Default.influxCertKeyFileName);
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
                        writeApi.EventHandler += (sender, eventArgs) =>
                        {
                            if (eventArgs is WriteErrorEvent @event)
                            {
                                var exception = @event.Exception;

                                EventLog.WriteEntry("TrackerAppService", $"InfluxDBClient: {exception.Message}", EventLogEntryType.Error);
                            }
                        };

                        DateTime now = DateTime.Now;
                        int dow = (int)now.DayOfWeek;

                        List<PointData> lpd = new List<PointData>();

                        foreach (var entry in appUsagePerDay)
                        {
                            TimeSpan tslimit = TimeSpan.FromDays(1);

                            if (appUsageLimits.ContainsKey(entry.Key))
                            {
                                tslimit = (TimeSpan)appUsageLimits[entry.Key].GetValue(dow);
                            }

                            var point = PointData.Measurement("tracker-app")
                                .Tag("host", Environment.MachineName)
                                .Tag("application", entry.Key)
                                .Field("run-time-minutes", (int)entry.Value.TotalMinutes)
                                .Field("limit-time-minutes", (int)tslimit.TotalMinutes)
                                .Timestamp(dt, WritePrecision.S);

                            lpd.Add(point);
                        }

                        if (_idle)
                        {
                            var point = PointData.Measurement("tracker-app")
                                .Tag("host", Environment.MachineName)
                                .Tag("application", "idle")
                                .Field("run-time-minutes", (int)1)
                                .Field("limit-time-minutes", (int)1)
                                .Timestamp(dt, WritePrecision.S);

                            lpd.Add(point);
                        }

                        if (lpd.Count > 0)
                        {
                            writeApi.WritePoints(lpd); //, Properties.Settings.Default.influxBucket, Properties.Settings.Default.influxOrg);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"Exception: {ex.Message}", EventLogEntryType.Error);
            }
            
        }

        protected override void OnStart(string[] args)
        {
            //Properties.Settings.Default.Save();

            if (!EventLog.SourceExists("TrackerAppService"))
            {
                EventLog.CreateEventSource("TrackerAppService", "Application");
            }

            using (RegistryKey rkey = Registry.LocalMachine.OpenSubKey(registryPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
            {
                if (rkey == null)
                {
                    using (RegistryKey rkeyNew = Registry.LocalMachine.CreateSubKey(registryPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                    {
                        RegistrySecurity rs = rkeyNew.GetAccessControl();

                        // Creating registry access rule for 'Everyone' NT account
                        RegistryAccessRule rar = new RegistryAccessRule(
                            "BUILTIN\\Users",
                            RegistryRights.FullControl,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                            PropagationFlags.None,
                            AccessControlType.Allow);

                        rs.AddAccessRule(rar);
                        rkeyNew.SetAccessControl(rs);
                    }
                }
            }

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
            appUsagePerDay.Clear();

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
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

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath + regUsage))
            {
                if (key != null)
                {
                    foreach (string appName in key.GetValueNames())
                    {
                        if (TimeSpan.TryParse(key.GetValue(appName).ToString(), out TimeSpan duration))
                        {
                            appUsagePerDay[appName] = duration;
                        }
                    }
                }
            }
        }



        private Dictionary<string, int> GetWinProcesses()
        {
            Dictionary<string, int> ret = new Dictionary<string, int>();

            DateTime now = DateTime.Now;
            TimeSpan dtdiff = now - DateTime.MinValue;
            string rkey = $"app-list-{((int)dtdiff.TotalMinutes)}";

            try
            {
                ProcessServices pss = new ProcessServices();

                if (pss.StartProcessAsCurrentUser(Process.GetCurrentProcess().MainModule.FileName + " " + rkey)) // "notepad"))
                {
                    string rk = registryPath + "\\" + rkey;
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(rk))
                    {
                        if (key != null)
                        {
                            foreach (string appName in key.GetValueNames())
                            {
                                //Debug.WriteLine(appName);
                                ret.Add(appName, (int)key.GetValue(appName));
                            } 
                        }
                    }

                    Registry.LocalMachine.DeleteSubKeyTree(rk, false);
                }

            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"Exception: {ex.Message}", EventLogEntryType.Error);
            }

            return ret;
        }


        private void TimerElapsed(object sender, ElapsedEventArgs e)
        {
            ResetUsageIfNewDay();

            Dictionary<string, int> procl = GetWinProcesses();

            foreach (var pl in procl)
            {
                if (!appUsagePerDay.ContainsKey(pl.Key))
                {
                    appUsagePerDay[pl.Key] = TimeSpan.Zero;
                }
                else
                {
                    appUsagePerDay[pl.Key] += TimeSpan.FromSeconds(10); //+10 sec
                }

                LogUsage(pl.Key);
                CheckUsageLimit(pl.Key, pl.Value);
            }
            
        }

        private void Timer1minElapsed(object sender, ElapsedEventArgs e)
        {
            SendDataToInfluxDB();
        }

        private void ResetUsageIfNewDay()
        {
            if (DateTime.Now.Date > lastResetDate.Date)
            {  
                SendDataToInfluxDB(lastResetDate.AddDays(1).AddMinutes(-1)); //lastResetDate 23.59.00

                appUsagePerDay.Clear();
                warnedApps.Clear();

                Registry.LocalMachine.DeleteSubKeyTree(registryPath + regUsage, false);

                SendDataToInfluxDB(lastResetDate.Date.AddDays(1).AddMinutes(1), true); //lastResetDate 00.01.00

                System.IO.File.Move(logFilePath, Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"AppUsage-{lastResetDate:yyyy-dd-MM}.log"));

                lastResetDate = DateTime.Now.Date;

                SaveUsageToRegistry();
            }
        }


        private void LogUsage(string appTitle)
        {
            TimeSpan duration = TimeSpan.Zero;
            DateTime now = DateTime.Now;

            TimeSpan remainingTime = TimeSpan.FromDays(1) - TimeSpan.FromSeconds(1);

            if (appUsageLimits.ContainsKey(appTitle))
            {
                int dow = (int)now.DayOfWeek; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 
                TimeSpan appLimit = (TimeSpan)appUsageLimits[appTitle].GetValue(dow);
                remainingTime = appLimit - appUsagePerDay[appTitle];
            }

            string signn = remainingTime < TimeSpan.Zero ? "-" : "";

            string logEntry = $"{now}: used:{appUsagePerDay[appTitle].ToString("hh\\:mm\\:ss")}, remains:{signn}{remainingTime.ToString("hh\\:mm\\:ss")}, {appTitle}";
            System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }

        private void CheckUsageLimit(string appTitle, int pid)
        {
            if (appUsagePerDay.ContainsKey(appTitle) && appUsageLimits.ContainsKey(appTitle))
            {
                DateTime now = DateTime.Now;
                int dow = (int)now.DayOfWeek; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 
                TimeSpan appLimit = (TimeSpan)appUsageLimits[appTitle].GetValue(dow);

                TimeSpan remainingTime = appLimit - appUsagePerDay[appTitle];                

                if (remainingTime <= TimeSpan.Zero)
                {
                    KillApplication(appTitle, pid);
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

            new ProcessServices().StartProcessAsCurrentUser(Process.GetCurrentProcess().MainModule.FileName + $" app-notify \"{title}\" \"{message}\"");

        }

        private void KillApplication(string appTitle, int pid)
        {
            foreach (var process in Process.GetProcessesByName(appTitle).Where(p => p.Id == pid))
            {
                process.Kill();

                string message = $"Usage time for {appTitle.ToUpper()} is expired for today!";
                string title = $"{appTitle.ToUpper()} Usage Limit Expired";

                new ProcessServices().StartProcessAsCurrentUser(Process.GetCurrentProcess().MainModule.FileName + $" app-notify \"{title}\" \"{message}\"");

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
                foreach (var entry in appUsagePerDay)
                {
                    writer.WriteLine($"{entry.Key}: {entry.Value}");
                }
            }
        }

        private void SaveUsageToRegistry()
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
            {
                key?.SetValue("LastResetDate", lastResetDate.ToString("yyyy-MM-dd"));
            }

            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath + regUsage))
            {
                if (key != null)
                {
                    foreach (var entry in appUsagePerDay)
                    {
                        key.SetValue(entry.Key, entry.Value.ToString());
                    }
                }
            }
        }

    }
}
