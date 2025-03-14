﻿using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;

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
                //EventLog.WriteEntry("TrackerAppService", $"Args: {args[0]}", EventLogEntryType.Warning);

                string registryPath = $"SOFTWARE\\TrackerAppService\\{args[0]}";

                Registry.LocalMachine.DeleteSubKeyTree(registryPath, false);

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        int cpid = Process.GetCurrentProcess().Id;

                        Process[] processList = Process.GetProcesses();

                        foreach (Process process in processList.Where(p => p.Id != cpid))
                        {
                            if (process.MainWindowHandle != IntPtr.Zero 
                             && IsWindowVisible(process.MainWindowHandle))
                            {
                                int cloakedVal = 0;
                                int result = DwmGetWindowAttribute(process.MainWindowHandle, DWMWA_CLOAKED, out cloakedVal, sizeof(int));

                                if ((result == 0 && cloakedVal != 0) == false) // 0 means success, and cloakedVal > 0 indicates a cloaked window
                                {
                                    Console.WriteLine($"{process.Id}, {process.ProcessName}, {process.MainWindowTitle}");

                                    key.SetValue(process.ProcessName == "ApplicationFrameHost" ? process.MainWindowTitle : process.ProcessName, process.Id);
                                }
                            }
                        }
                    }
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
