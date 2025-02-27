using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Xaml.Controls;

namespace TrackerAppService
{
    static class Program
    {
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



            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[] 
            { 
                new TrackerAppService() 
            };

            ServiceBase.Run(ServicesToRun);
        }
    }
}
