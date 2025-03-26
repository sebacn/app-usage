using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;
using System.Windows.Forms;

namespace TrackerAppService
{
    static class Program
    {
        private const int DWMWA_CLOAKED = 14;

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        internal static extern bool IsWindowVisible(IntPtr hwnd);

        [DllImport("dwmapi.dll", EntryPoint = "DwmGetWindowAttribute")]
        internal static extern int DwmGetWindowAttribute(IntPtr IntPtr, int dwAttribute, out int pvAttribute, uint cbAttribute);

        public static void psNotifyUser(string title, string message)
        {

            var ps1File = "msgNotify.ps1";

            var startInfo = new ProcessStartInfo()
            {
                CreateNoWindow = true,
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy ByPass -File \"{ps1File}\" -mtitle \"{title}\" -mtext \"{message}\"",
                UseShellExecute = false,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
            };
            Process.Start(startInfo);

        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main(string[] args)
        {
            
            if (args != null && args.Length > 0 && args[0].StartsWith("app-list-"))
            {
                int cupid = Process.GetCurrentProcess().Id;

                Dictionary<string, int> appList = new Dictionary<string, int>();

                Process[] processList = Process.GetProcesses();

                foreach (Process process in processList.Where(p => p.Id != cupid))
                {
                    if (process.MainWindowHandle != IntPtr.Zero 
                        && IsWindowVisible(process.MainWindowHandle))
                    {
                        int cloakedVal = 0;
                        int result = DwmGetWindowAttribute(process.MainWindowHandle, DWMWA_CLOAKED, out cloakedVal, sizeof(int));

                        if ((result == 0 && cloakedVal != 0) == false) // 0 means success, and cloakedVal > 0 indicates a cloaked window
                        {
                            //Console.WriteLine($"{process.Id}, {process.ProcessName}, {process.MainWindowTitle}");

                            string appName = process.ProcessName == "ApplicationFrameHost" ? process.MainWindowTitle : process.ProcessName;

                            if (!appList.ContainsKey(appName))
                            {
                                appList.Add(appName, process.Id);
                            }
                        }
                    }
                }

                string json = JsonSerializer.Serialize(appList, new JsonSerializerOptions { WriteIndented = true });

                string appListFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppList.json");

                try
                {
                    System.IO.File.WriteAllText(appListFilePath, json);
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("TrackerAppService", $"Exception (main.WriteAllText): {ex.Message}", EventLogEntryType.Error);
                }                

                return;
            }

            if (args != null && args.Length >= 3 && args[0].StartsWith("app-notify"))
            {
                psNotifyUser(args[1], args[2]);
                return;
            }


            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[] 
            { 
                new TrackerAppService() 
            };

            ServiceBase.Run(ServicesToRun);
        }
    }
}
