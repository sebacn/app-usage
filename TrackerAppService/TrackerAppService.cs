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
using System.Linq;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections;
using Windows.UI.Composition;
using System.IO.Pipes;
using System.Threading.Tasks;
using System.Threading;
using System.Windows.Forms;
using System.Windows.Input;
using Windows.System;
//using Windows.UI.Xaml.Shapes;

namespace TrackerAppService 
{
 

    public partial class TrackerAppService : ServiceBase
    {

        private System.Timers.Timer timer, timer1min;
        private Dictionary<string, TimeSpan> appUsagePerDay = new Dictionary<string, TimeSpan>();
        private Dictionary<string, TimeSpan[]> appUsageLimits = new Dictionary<string, TimeSpan[]>();
        private HashSet<string> warnedApps = new HashSet<string>();
        private HashSet<string> trackedApps = new HashSet<string>();
        private DateTime lastResetDate = DateTime.Now.Date;
        Dictionary<DateTime, List<PointData>> cachePointData = new Dictionary<DateTime, List<PointData>>();
        private PowerBroadcastStatus currPowerStatus;
        CancellationTokenSource pipeServerCTS = new CancellationTokenSource();
        Task pipeTask = null;
        Progress<Dictionary<string, int>> tprogress = new Progress<Dictionary<string, int>>();

        string logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsage.log");
        string cacheFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppCachePointDataInfluxDB.json");
        string appUsageFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsage.json");
        string lastResetDateFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppLastResetDate.json");
        //string appListFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppList.json");

        public TrackerAppService()
        {
            EventLog.WriteEntry("TrackerAppService", "Service class initialized", EventLogEntryType.Information);
            InitializeComponent();
        }

        // Destructor
        ~TrackerAppService()
        {
            EventLog.WriteEntry("TrackerAppService", "Service class destructed", EventLogEntryType.Information);
        }

        private bool InfluxDBConfigOk()
        {
            return (!string.IsNullOrEmpty(Properties.Settings.Default.influxUrl)
                && !string.IsNullOrEmpty(Properties.Settings.Default.influxToken)
                && !string.IsNullOrEmpty(Properties.Settings.Default.influxOrg)
                && !string.IsNullOrEmpty(Properties.Settings.Default.influxBucket));
        }

        List<PointData>  GetPointDataList(DateTime dt)
        {
            List<PointData> ret = new List<PointData>();

            DateTime now = DateTime.Now;
            int dow = (int)now.DayOfWeek;

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

                ret.Add(point);
            }

            return ret;
        }

        private void SendDataToInfluxDB(DateTime? _dt = null)
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

                        List<PointData> lpd =  GetPointDataList(dt);

                        if (cachePointData.Count > 0)
                        {
                            foreach (var item in cachePointData)
                            {
                                if (dt != item.Key)
                                {
                                    lpd.AddRange(item.Value);
                                }
                            }
                        }

                        if (lpd.Count > 0)
                        {
                            writeApi.WritePoints(lpd); //, Properties.Settings.Default.influxBucket, Properties.Settings.Default.influxOrg);
                        }
                    }
                }

                cachePointData.Clear(); //clear cache if data sent ok
     
            }
            catch (Exception ex)
            {

                if (!cachePointData.ContainsKey(dt))
                {
                    List<PointData> lpd = GetPointDataList(dt);

                    cachePointData.Add(dt, lpd);
                }

                EventLog.WriteEntry("TrackerAppService", $"Exception: {ex.Message}", EventLogEntryType.Error);
            }

            if (cachePointData.Count == 0 
             && System.IO.File.Exists(cacheFilePath))
            {
                System.IO.File.Delete(cacheFilePath);
            }

        }

        protected override void OnStart(string[] args)
        {
            //Properties.Settings.Default.Save();

            if (!EventLog.SourceExists("TrackerAppService"))
            {
                EventLog.CreateEventSource("TrackerAppService", "Application");
            }

            EventLog.WriteEntry("TrackerAppService", "Service started", EventLogEntryType.Information);

            LoadTrackedApps();
            LoadUsageAndCacheFromFIle();

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

            RunPipeServer();
        }

        protected override void OnStop()
        {
            EventLog.WriteEntry("TrackerAppService", "Service stopped", EventLogEntryType.Information);

            timer.Stop();
            timer.Dispose();

            pipeServerCTS.Cancel();
            pipeTask.Wait(1000);

            if (timer1min != null)
            {
                timer1min.Stop();
                timer1min.Dispose();
            }

            SummarizeUsage();
            SaveUsageAndCacheToFIle();

            DateTime now = DateTime.Now;
            string logEntry = $"{now}: TrackerAppService stopped";
            System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }

        protected override bool OnPowerEvent(System.ServiceProcess.PowerBroadcastStatus powerStatus)
        {
            currPowerStatus = powerStatus;
            EventLog.WriteEntry("TrackerAppService", $"Power event: {powerStatus}", EventLogEntryType.Warning);
            return true;
        }

        private void RunPipeServer()
        {

            pipeServerCTS = new CancellationTokenSource();

            tprogress.ProgressChanged += (s, appList) =>
            {
                foreach (var pl in appList)
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

                //EventLog.WriteEntry("TrackerAppService", $"ProgressChanged: {string.Join(", ", appList.Keys.ToArray())}", EventLogEntryType.Warning);
            };

            pipeTask = Task.Run(() => RunPipeServerAsync(tprogress, pipeServerCTS.Token));

            pipeTask.GetAwaiter().OnCompleted(() =>
            {
                EventLog.WriteEntry("TrackerAppService", $"Task completed", EventLogEntryType.SuccessAudit);
            });
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

            if (System.IO.File.Exists(cacheFilePath))
            {
                string json = System.IO.File.ReadAllText(cacheFilePath);
                cachePointData = JsonSerializer.Deserialize<Dictionary<DateTime, List<PointData>>>(json) ?? new Dictionary<DateTime, List<PointData>>();
            }
        }


        private void TimerElapsed(object sender, ElapsedEventArgs e)
        {
            ResetUsageIfNewDay();

            try
            {
                ProcessServices pss = new ProcessServices();
                string rkey = $"app-list-123";

                pss.StartProcessAsCurrentUser(Process.GetCurrentProcess().MainModule.FileName + " " + rkey);
                
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"Exception (GetWinProcesses): {ex.Message}", EventLogEntryType.Error);
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

                List<string> keys = new List<string>(appUsagePerDay.Keys);

                foreach (string key in keys)
                {
                    appUsagePerDay[key] = TimeSpan.Zero;
                }

                SendDataToInfluxDB(lastResetDate.AddDays(1)); //new Date 00.00.00

                appUsagePerDay.Clear();
                warnedApps.Clear();

                System.IO.File.Move(logFilePath, Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"AppUsage-{lastResetDate:yyyy-dd-MM}.log"));

                lastResetDate = DateTime.Now.Date;

                SaveUsageAndCacheToFIle();
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

        private void SaveUsageAndCacheToFIle()
        {
            System.IO.File.WriteAllText(lastResetDateFilePath, lastResetDate.ToString("yyyy-MM-dd"));

            string json = JsonSerializer.Serialize(appUsagePerDay, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(appUsageFilePath, json);

            if (cachePointData.Count > 0)
            {
                json = JsonSerializer.Serialize(cachePointData, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(cacheFilePath, json);
            }
            else if (System.IO.File.Exists(cacheFilePath))
            {
                System.IO.File.Delete(cacheFilePath);
            }
        }

        private void LoadUsageAndCacheFromFIle()
        {
            appUsagePerDay.Clear();

            lastResetDate = DateTime.Now.Date;

            if (System.IO.File.Exists(lastResetDateFilePath))
            {
                string resetDateValue = System.IO.File.ReadAllText(lastResetDateFilePath);

                if (!string.IsNullOrEmpty(resetDateValue) && DateTime.TryParse(resetDateValue, out DateTime resetDate))
                {
                    lastResetDate = resetDate;
                }
            }
            else
            {
                System.IO.File.WriteAllText(lastResetDateFilePath, lastResetDate.ToString("yyyy-MM-dd"));
            }

            if (System.IO.File.Exists(appUsageFilePath))
            {
                string json = System.IO.File.ReadAllText(appUsageFilePath);
                appUsagePerDay = JsonSerializer.Deserialize<Dictionary<string, TimeSpan>>(json) ?? new Dictionary<string, TimeSpan>();
            }
            else
            {
                string json = JsonSerializer.Serialize(appUsagePerDay, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appUsageFilePath, json);
            }

            if (System.IO.File.Exists(cacheFilePath))
            {
                string json = System.IO.File.ReadAllText(cacheFilePath);
                cachePointData = JsonSerializer.Deserialize< Dictionary < DateTime, List < PointData >>> (json) ?? new Dictionary<DateTime, List<PointData>>();
            }

        }

        private static async Task RunPipeServerAsync(IProgress<Dictionary<string, int>> progress, CancellationToken ct)
        {
            EventLog.WriteEntry("TrackerAppService", $"Task started", EventLogEntryType.SuccessAudit);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    string json = "";
                    Dictionary<string, int> appList = new Dictionary<string, int>();

                    PipeSecurity pipeSecurity = new PipeSecurity();
                    pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow));
                    pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

                    using (var pserver = new NamedPipeServerStream("TrackerAppService.pipe", PipeDirection.InOut, 10, PipeTransmissionMode.Message, PipeOptions.WriteThrough, 1024, 1024, pipeSecurity))
                    {
                        await pserver.WaitForConnectionAsync(ct);

                        StreamReader reader = new StreamReader(pserver);

                        json = reader.ReadToEnd();

                        pserver.Disconnect();
                        pserver.Dispose();
                        pserver.Close();
                    }

                    if (json != "")
                    {
                        appList = JsonSerializer.Deserialize<Dictionary<string, int>>(json) ?? new Dictionary<string, int>();

                        progress.Report(appList);
                    }
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("TrackerAppService", $"Exception (RunPipeServerAsync): {ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                }
            }

            EventLog.WriteEntry("TrackerAppService", $"Task exit", EventLogEntryType.SuccessAudit);
        }

    }
}
