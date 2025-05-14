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
using Microsoft.Win32;
using Windows.Devices.Custom;
using System.Runtime.InteropServices;
using Newtonsoft.Json.Linq;
using System.Net.Sockets;
using System.Net;
using System.Xml.Linq;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text;
//using Windows.UI.Xaml.Shapes;

namespace TrackerAppService 
{

    public class SettingsInflux
    {
        public bool Enabled { get; set; } = false;
        public string Url { get; set; } = "";
        public string Org { get; set; } = "";
        public string Bucket { get; set; } = "";
        public string CertName { get; set; } = "";

        [JsonInclude]
        private byte[] TokenCRT { get; set; } = new byte[10];
        [JsonInclude]
        private byte[] CertPassCRT { get; set; } = new byte[10];
        [JsonInclude]
        private byte[] EntrCRT { get; set; } = new byte[20];
        

        public SettingsInflux()
        {

            // Generate additional entropy (will be used as the Initialization vector)
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(EntrCRT);
            }
        }

        [JsonIgnore]
        public string Token
        {
            get
            {
                string ret = "";

                try
                {
                    byte[] plaintext = ProtectedData.Unprotect(TokenCRT, EntrCRT, DataProtectionScope.LocalMachine);

                    ret = Encoding.UTF8.GetString(plaintext);
                }
                catch { }

                return ret;
            }
            set
            {
                try
                {
                    TokenCRT = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), EntrCRT, DataProtectionScope.LocalMachine);
                }
                catch { }

            }
        }

        [JsonIgnore]
        public string CertPass
        {
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

    public class DataPoint
    {
        public String Host { get; set; }
        public String IP { get; set; }
        public String Application { get; set; }
        public int RunTimeMinutes { get; set; }
        public int LimitTimeMinutes { get; set; }
    }

    public class AppLimitConfig
    {
        public String AppName { get; set; }
        public TimeSpan ActiveFromTime { get; set; }
        public TimeSpan ActiveToTime { get; set; }
        public  Dictionary<DayOfWeek, TimeSpan> UsageLimitsPerDay { get; set; }

        public void initDefault(string _appName)
        {
            AppName = _appName;
            ActiveFromTime = TimeSpan.FromMinutes(1);
            ActiveToTime = TimeSpan.FromHours(24) + TimeSpan.FromMinutes(-1);

            UsageLimitsPerDay = new Dictionary<DayOfWeek, TimeSpan>();

            for (int i = 0; i < 7; i++)
            {
                DayOfWeek dow = (DayOfWeek)i;
                UsageLimitsPerDay.Add(dow, TimeSpan.FromHours(24) + TimeSpan.FromMinutes(-1));
            } 
        }
    }

    public partial class TrackerAppService : ServiceBase
    {
        public bool LogDataPoint;

        private System.Timers.Timer timer10sec, timer1min;
        public Dictionary<string, TimeSpan> appUsagePerDay = new Dictionary<string, TimeSpan>();
        private HashSet<string> warnedApps = new HashSet<string>();
        //private HashSet<string> trackedApps = new HashSet<string>();
        public DateTime lastResetDate = DateTime.Now.Date;
        CancellationTokenSource pipeServerCTS = new CancellationTokenSource();
        Task pipeTask = null;
        Progress<Dictionary<string, int>> tprogress = new Progress<Dictionary<string, int>>();

        string logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsage.log");
        string influxPointBuffFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppInfluxDB2PointData.json");
        string appUsageFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsage.json");
        string appUsageLimitsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppUsageLimits.json");
        string lastResetDateFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppLastResetDate.json");
        string pointDataLogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppPointDataLog.json");
        public string influxConfigFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppInfluxConfig.json");
        bool IsSessionLocked = false;

        Dictionary<DateTime, List<DataPoint>> InfluxPointBuff = new Dictionary<DateTime, List<DataPoint>>();
        public Dictionary<string, AppLimitConfig> appUsageLimitsDict = new Dictionary<string, AppLimitConfig>();

        public SettingsInflux influxConfig = null;

        public TrackerAppService()
        {
            EventLog.WriteEntry("TrackerAppService", "Service class initialized", EventLogEntryType.Information);

            var cclone = Thread.CurrentThread.CurrentCulture.Clone() as CultureInfo;
            cclone.DateTimeFormat = CultureInfo.GetCultureInfo("en-GB").DateTimeFormat;
            cclone.NumberFormat.NumberDecimalSeparator = ".";

            Thread.CurrentThread.CurrentCulture = cclone;

            InitializeComponent();
        }

        // Destructor
        ~TrackerAppService()
        {
            EventLog.WriteEntry("TrackerAppService", "Service class destructed", EventLogEntryType.Information);
        }

        private bool InfluxDBConfigOk()
        {
            return (influxConfig.Enabled
                && !string.IsNullOrEmpty(influxConfig.Url)
                && !string.IsNullOrEmpty(influxConfig.Token)
                && !string.IsNullOrEmpty(influxConfig.Org)
                && !string.IsNullOrEmpty(influxConfig.Bucket));
        }

        public void AddInfluxPointData(DateTime dt)
        {
            List<DataPoint> ret = new List<DataPoint>();

            ResetUsageIfNewDay();

            DateTime dtnow = DateTime.Now;

            foreach (var entry in appUsagePerDay.Where(k => (int)k.Value.TotalMinutes >= 1 || k.Value == TimeSpan.Zero))
            {
                TimeSpan tslimit = TimeSpan.FromDays(1);

                if (appUsageLimitsDict.ContainsKey(entry.Key))
                {
                    tslimit = appUsageLimitsDict[entry.Key].UsageLimitsPerDay[dtnow.DayOfWeek];
                }

                var point = new DataPoint {
                    Host = Environment.MachineName,
                    IP = GetLocalIPAddress(),
                    Application = entry.Key,
                    RunTimeMinutes = (int)entry.Value.TotalMinutes,
                    LimitTimeMinutes = (int)tslimit.TotalMinutes
                };

                ret.Add(point);
            }

            InfluxPointBuff.Add(dt, ret);

            //remove zero items
            List<string> keys = new List<string>(appUsagePerDay.Keys);

            foreach (string key in keys.Where(k => appUsagePerDay[k] == TimeSpan.Zero))
            {
                appUsagePerDay.Remove(key);
            }

            //log
            if (InfluxPointBuff.ContainsKey(dt) && InfluxPointBuff[dt].Count > 0 && LogDataPoint)
            {
                Dictionary<DateTime, List<DataPoint>> logret = new Dictionary<DateTime, List<DataPoint>>
                {
                    { dt, ret }
                };

                var json = JsonSerializer.Serialize(logret, new JsonSerializerOptions { WriteIndented = true });

                try
                {
                    System.IO.File.AppendAllText(pointDataLogFilePath, json);
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                }
            }
        }

        private void SendDataToInfluxDB()//DateTime? _dt = null)
        { 

            if (!InfluxDBConfigOk() || IsSessionLocked || InfluxPointBuff.Count == 0)
            {
                return;
            }

            //DateTime dt = _dt ?? DateTime.UtcNow;
            List<PointData> lpd = new List<PointData>();
            List<DateTime> keys = new List<DateTime>();

            try
            {
                //lpd = GetPointDataList(dt);

                X509Certificate2 x509Certificate2 = null;

                if (!string.IsNullOrEmpty(influxConfig.CertName))
                {
                    string influxCertKeyFilePath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, influxConfig.CertName);
                    if (System.IO.File.Exists(influxCertKeyFilePath))
                    {
                        string influxCertKeyPass = string.IsNullOrEmpty(influxConfig.CertPass) ? "" : influxConfig.CertPass;

                        x509Certificate2 = new X509Certificate2(influxCertKeyFilePath, influxCertKeyPass, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet); //"C:\\Temp\\cert.pfx"
                    }
                }

                var options = new InfluxDBClientOptions(influxConfig.Url)
                {
                    Token = influxConfig.Token,
                    Org = influxConfig.Org,
                    Bucket = influxConfig.Bucket,
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
                                var ex = @event.Exception;

                                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);

                                throw ex;
                            }
                        };

                        /*
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
                        */

                        keys = new List<DateTime>(InfluxPointBuff.Keys);

                        foreach (var key in keys)
                        {
                            List<DataPoint> listPoints = InfluxPointBuff[key];

                            foreach (var point in listPoints)
                            {
                                var influxPoint = PointData.Measurement("tracker-app")
                                    .Tag("host", point.Host)
                                    .Tag("ip", point.IP)
                                    .Tag("application", point.Application)
                                    .Field("run-time-minutes", point.RunTimeMinutes)
                                    .Field("limit-time-minutes", point.LimitTimeMinutes)
                                    .Timestamp(key, WritePrecision.S);

                                lpd.Add(influxPoint);
                            }
                            
                        }

                        if (lpd.Count > 0)
                        {
                            writeApi.WritePoints(lpd); //, Properties.Settings.Default.influxBucket, Properties.Settings.Default.influxOrg);
                        }
                    }
                }

                //remove processed keys
                foreach (var key in keys)
                {
                    InfluxPointBuff.Remove(key);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }
        }

        protected override void OnStart(string[] args)
        {
            //Properties.Settings.Default.Save();

            if (args != null && args.Length > 0 && args[0].StartsWith("LogDataPointEnable"))
            {
                LogDataPoint = true;
            }

            if (!EventLog.SourceExists("TrackerAppService"))
            {
                EventLog.CreateEventSource("TrackerAppService", "Application");
            }

            EventLog.WriteEntry("TrackerAppService", "Service started", EventLogEntryType.Information);

            //LoadTrackedApps();
            LoadUsageAndCacheFromFIle();

            timer10sec = new System.Timers.Timer(10000); // Logs every 10 seconds
            timer10sec.Elapsed += TimerElapsed10sec;
            timer10sec.Start();

            //Thread.Sleep(30000); // debug

            if (InfluxDBConfigOk())
            {
                timer1min = new System.Timers.Timer(60000); // Logs every 1 min
                timer1min.Elapsed += Timer1minElapsed;
                timer1min.Start();
            }

            DateTime now = DateTime.Now;
            string logEntry = $"{now}: TrackerAppService started";

            try
            {
                System.IO.File.AppendAllText(logFilePath, Environment.NewLine + logEntry);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }

            SummarizeUsage();

            RunPipeServer();

            //Thread.Sleep(30000); // debug

            Task.Run(() => HttpServer.RunWebServerAsync(pipeServerCTS.Token, this));
            
        }

        protected override void OnStop()
        {
            EventLog.WriteEntry("TrackerAppService", "Service stopped", EventLogEntryType.Information);

            timer10sec.Stop();
            timer10sec.Dispose();

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

            try
            { 
                System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }
        }


        protected override void OnSessionChange(SessionChangeDescription desc)
        {
            switch (desc.Reason)
            {
                case SessionChangeReason.SessionLogon:
                case SessionChangeReason.SessionUnlock:
                    //var user = CustomService.UserInformation(desc.SessionId);
                    IsSessionLocked = false;
                    break;

                
                case SessionChangeReason.SessionLogoff:
                    SaveUsageAndCacheToFIle();
                    IsSessionLocked = true;
                    break;

                case SessionChangeReason.SessionLock:
                    IsSessionLocked = true;
                    break;
            }

            EventLog.WriteEntry("TrackerAppService", $"sid:{desc.SessionId}, {desc.Reason}", EventLogEntryType.Information);
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
                    
                    appUsagePerDay[pl.Key] += TimeSpan.FromSeconds(10); //+10 sec

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

        /*
        private void LoadTrackedApps()
        {
            appUsageLimitsDict.Clear();

            if (System.IO.File.Exists(appUsageLimitsFilePath))
            {
                string json = System.IO.File.ReadAllText(appUsageLimitsFilePath);
                appUsageLimitsDict = JsonSerializer.Deserialize<Dictionary<string, AppLimitConfig>> (json) ?? new Dictionary<string, AppLimitConfig>();
            }

            if (System.IO.File.Exists(influxPointBuffFilePath))
            {
                string json = System.IO.File.ReadAllText(influxPointBuffFilePath);
                InfluxPointBuff = JsonSerializer.Deserialize<Dictionary<DateTime, List<DataPoint>>>(json) ?? new Dictionary<DateTime, List<DataPoint>>();
            }
        }
        */

        private void TimerElapsed10sec(object sender, ElapsedEventArgs e)
        {

            if (IsSessionLocked)
            {
                return;
            }

            try
            {
                ProcessServices pss = new ProcessServices();
                string rkey = $"app-list-123";

                pss.StartProcessAsCurrentUser(Process.GetCurrentProcess().MainModule.FileName + " " + rkey);
                
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }

        }

        private void Timer1minElapsed(object sender, ElapsedEventArgs e)
        {
            if (InfluxDBConfigOk())
            {
                AddInfluxPointData(DateTime.UtcNow);

                SendDataToInfluxDB();
            }
        }

        private void ResetUsageIfNewDay()
        {
            if (DateTime.Now.Date > lastResetDate.Date)
            {
                var newDate = lastResetDate.Date.AddDays(1);

                EventLog.WriteEntry("TrackerAppService", $"Date now: {DateTime.Now.Date}, Last reset date: {lastResetDate.Date}, New date: {newDate}", EventLogEntryType.Warning);

                lastResetDate = DateTime.Now.Date;
               
                AddInfluxPointData(newDate.AddMinutes(-1).ToUniversalTime());

                List<string> keys = new List<string>(appUsagePerDay.Keys);

                foreach (string key in keys)
                {
                    appUsagePerDay[key] = TimeSpan.Zero;
                }

                AddInfluxPointData(newDate.ToUniversalTime()); //new Date 00.00.00

                //appUsagePerDay.Clear(); // cleared in SendDataToInfluxDB
                warnedApps.Clear();

                try
                { 
                    System.IO.File.Move(logFilePath, Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"AppUsage-{lastResetDate:yyyy-dd-MM}.log"));
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                }

                

                SaveUsageAndCacheToFIle();
            }
        }


        private void LogUsage(string appTitle)
        {
            TimeSpan duration = TimeSpan.Zero;
            DateTime dtnow = DateTime.Now;

            TimeSpan remainingTime = TimeSpan.FromDays(1) - TimeSpan.FromSeconds(1);

            if (appUsageLimitsDict.ContainsKey(appTitle))
            {
                TimeSpan appLimit = appUsageLimitsDict[appTitle].UsageLimitsPerDay[dtnow.DayOfWeek]; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 

                remainingTime = appLimit - appUsagePerDay[appTitle];
            }

            string signn = remainingTime < TimeSpan.Zero ? "-" : "";

            string logEntry = $"{dtnow}: used:{appUsagePerDay[appTitle].ToString("hh\\:mm\\:ss")}, remains:{signn}{remainingTime.ToString("hh\\:mm\\:ss")}, {appTitle}";

            try
            { 
                System.IO.File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }
        }

        private void CheckUsageLimit(string appTitle, int pid)
        {
            if (appUsagePerDay.ContainsKey(appTitle) && appUsageLimitsDict.ContainsKey(appTitle))
            {
                DateTime dtnow = DateTime.Now;

                var appCfg = appUsageLimitsDict[appTitle];

                TimeSpan appLimit = appCfg.UsageLimitsPerDay[dtnow.DayOfWeek]; // DayOfWeek.Sunday 0 to DayOfWeek.Saturday 6 

                TimeSpan remainingTime = appLimit - appUsagePerDay[appTitle];

                if (remainingTime <= TimeSpan.FromMinutes(5) && !warnedApps.Contains(appTitle))
                {
                    ShowWarningDialog(appTitle, remainingTime);
                    warnedApps.Add(appTitle);
                }

                TimeSpan timeNow = dtnow - dtnow.Date;

                if (appCfg.ActiveToTime - TimeSpan.FromMinutes(5) <= timeNow && !warnedApps.Contains(appTitle))
                {
                    ShowWarningDialog(appTitle, remainingTime);
                    warnedApps.Add(appTitle);
                }

                if (appCfg.ActiveToTime <= timeNow || appCfg.ActiveFromTime > timeNow)
                {
                    remainingTime = TimeSpan.Zero;
                }

                if (remainingTime <= TimeSpan.Zero)
                {
                    KillApplication(appTitle, pid);
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
            var process = Process.GetProcessById(pid); // GetProcessesByName(appTitle)) // .Where(p => p.Id == pid))
            
            if (process != null)
            {
                process.Kill();

                string message = $"Usage time for {appTitle.ToUpper()} is expired for today!";
                string title = $"{appTitle.ToUpper()} Usage Limit Expired";

                new ProcessServices().StartProcessAsCurrentUser(Process.GetCurrentProcess().MainModule.FileName + $" app-notify \"{title}\" \"{message}\"");
            }
            else
            {
                EventLog.WriteEntry("TrackerAppService", $"Failed to stop process name: {appTitle}, id: {pid}", EventLogEntryType.Error);
            }
        }

        private void SummarizeUsage()
        {
            try
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
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }
        }

        private void SaveUsageAndCacheToFIle()
        {
            try
            {
                System.IO.File.WriteAllText(lastResetDateFilePath, lastResetDate.ToString("yyyy-MM-dd"));

                string json = JsonSerializer.Serialize(appUsagePerDay, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appUsageFilePath, json);

                if (InfluxPointBuff.Count > 0)
                {
                    json = JsonSerializer.Serialize(InfluxPointBuff, new JsonSerializerOptions { WriteIndented = true });
                    System.IO.File.WriteAllText(influxPointBuffFilePath, json);
                }
                else if (System.IO.File.Exists(influxPointBuffFilePath))
                {
                    System.IO.File.Delete(influxPointBuffFilePath);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
            }
        }

        public void SaveAppUsageLimitsToFile()
        {
            try
            {
                string json = JsonSerializer.Serialize(appUsageLimitsDict, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appUsageLimitsFilePath, json);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
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

            if (System.IO.File.Exists(influxPointBuffFilePath))
            {
                string json = System.IO.File.ReadAllText(influxPointBuffFilePath);
                InfluxPointBuff = JsonSerializer.Deserialize< Dictionary < DateTime, List <DataPoint>>> (json) ?? new Dictionary<DateTime, List<DataPoint>>();
            }

            appUsageLimitsDict.Clear();

            if (System.IO.File.Exists(appUsageLimitsFilePath))
            {
                string json = System.IO.File.ReadAllText(appUsageLimitsFilePath);
                appUsageLimitsDict = JsonSerializer.Deserialize<Dictionary<string, AppLimitConfig>>(json) ?? new Dictionary<string, AppLimitConfig>();
            }
            else
            {
                //write default

                if (appUsageLimitsDict.Count == 0)
                {
                    var appCfg = new AppLimitConfig();
                    appCfg.initDefault("notepad");

                    appUsageLimitsDict.Add(appCfg.AppName, appCfg);
                }

                string json = JsonSerializer.Serialize(appUsageLimitsDict, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(appUsageLimitsFilePath, json);
            }

            //influx config
            if (System.IO.File.Exists(influxConfigFilePath))
            {
                string json = System.IO.File.ReadAllText(influxConfigFilePath);
                influxConfig = JsonSerializer.Deserialize<SettingsInflux>(json) ?? new SettingsInflux();
            }
            else
            {
                string json = JsonSerializer.Serialize(influxConfig, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(influxConfigFilePath, json);
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
                    EventLog.WriteEntry("TrackerAppService", $"{ex.Message}, trace: {ex.StackTrace}", EventLogEntryType.Error);
                }
            }

            EventLog.WriteEntry("TrackerAppService", $"Task exit", EventLogEntryType.SuccessAudit);
        }

        public string GetLocalIPAddress()
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

        /*
        private static User UserInformation(int sessionId)
        {
            IntPtr buffer;
            int length;

            var user = new User();

            if (NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionId, NativeMethods.WTS_INFO_CLASS.WTSUserName, out buffer, out length) && length > 1)
            {
                user.Name = Marshal.PtrToStringAnsi(buffer);

                NativeMethods.WTSFreeMemory(buffer);
                if (NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionId, NativeMethods.WTS_INFO_CLASS.WTSDomainName, out buffer, out length) && length > 1)
                {
                    user.Domain = Marshal.PtrToStringAnsi(buffer);
                    NativeMethods.WTSFreeMemory(buffer);
                }
            }

            if (user.Name.Length == 0)
            {
                return null;
            }

            return user;
        }
        */

    }
}
