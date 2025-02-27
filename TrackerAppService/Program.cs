using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.ServiceProcess;

namespace TrackerAppService
{
    static class Program
    {


        public static void psNotifyUser(string title, string message)
        {

            var ps1File = "msgNotify.ps1";

            var startInfo = new ProcessStartInfo()
            {

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
            
        //string arg = "nulll";
            if (args != null && args.Length > 0 && args[0].StartsWith("app-list-"))
            {
                //EventLog.WriteEntry("TrackerAppService", $"Args: {args[0]}", EventLogEntryType.Warning);

                string registryPath = $"SOFTWARE\\TrackerAppService\\{args[0]}";

                Registry.LocalMachine.DeleteSubKeyTree(registryPath, false);

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        Process[] processList = Process.GetProcesses();

                        foreach (Process process in processList)
                        {
                            if (process.MainWindowHandle != IntPtr.Zero)
                            {
                                Console.WriteLine($"{process.Id}, {process.ProcessName}, {process.MainWindowTitle}");

                                key.SetValue(process.ProcessName, process.SessionId);
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
