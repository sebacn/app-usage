using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class SessionProcessLauncher
{
    // Public API: runs an executable in the active console session and returns created process id or -1 on failure.
    // service must run as LocalSystem (or account with SeAssignPrimaryTokenPrivilege & SeIncreaseQuotaPrivilege)
    public static int RunProcessInActiveSession(string applicationPath, uint userSessionId, string arguments = null)
    {
        if (string.IsNullOrEmpty(applicationPath))
            throw new ArgumentNullException(nameof(applicationPath));

        if (userSessionId == 0)
        {
            userSessionId = WTSGetActiveConsoleSessionId();
        }
        //uint activeSessionId = WTSGetActiveConsoleSessionId();

        if (userSessionId == 0xFFFFFFFF) // no active session
            throw new InvalidOperationException("No active console session found.");

        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        try
        {
            // Query the user token for the active session
            if (!WTSQueryUserToken(userSessionId, out userToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WTSQueryUserToken failed.");

            // Duplicate to get a primary token (required for CreateProcessAsUser)
            const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
            const uint TOKEN_DUPLICATE = 0x0002;
            const uint TOKEN_QUERY = 0x0008;
            const uint TOKEN_ADJUST_DEFAULT = 0x0080;
            const uint TOKEN_ADJUST_SESSIONID = 0x0100;
            uint desiredAccess = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);

            if (!DuplicateTokenEx(userToken, desiredAccess, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, out primaryToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed.");

            // Enable required privileges in current process token (SeAssignPrimaryTokenPrivilege & SeIncreaseQuotaPrivilege)
            EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            EnablePrivilege("SeIncreaseQuotaPrivilege");

            // Create environment for the user
            if (!CreateEnvironmentBlock(out environment, primaryToken, false))
            {
                // fallback: environment is optional; continue without it but log
                environment = IntPtr.Zero;
            }

            // Build command line
            var cmd = new StringBuilder();
            cmd.Append('"').Append(applicationPath).Append('"');
            if (!string.IsNullOrEmpty(arguments))
            {
                cmd.Append(' ').Append(arguments);
            }

            // Prepare startup info
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            // show window on interactive desktop
            si.lpDesktop = "winsta0\\default";

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Create the process in the user's session using CreateProcessAsUser
            bool result = CreateProcessAsUser(
                primaryToken,
                null,
                cmd,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                environment,
                null,
                ref si,
                out pi);

            if (!result)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser failed.");

            // Close handles we don't need
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);

            return (int)pi.dwProcessId;
        }
        finally
        {
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    #region Privilege helper

    private static void EnablePrivilege(string privName)
    {
        if (string.IsNullOrEmpty(privName)) throw new ArgumentNullException(nameof(privName));
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr tokenHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");

        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, privName, out luid))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValue failed.");

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AdjustTokenPrivileges failed.");

            int err = Marshal.GetLastWin32Error();
            if (err != 0)
                throw new Win32Exception(err, "AdjustTokenPrivileges returned error.");
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    #endregion

    #region Native definitions

    private const int SE_PRIVILEGE_ENABLED = 0x2;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const int TOKEN_QUERY = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    #endregion
}
