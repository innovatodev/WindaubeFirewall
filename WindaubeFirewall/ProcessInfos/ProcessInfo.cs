using System.Runtime.InteropServices;
using System.Management;
using System.Diagnostics;
using System.Text;
using System.IO;
using System.Collections.Concurrent;

namespace WindaubeFirewall.ProcessInfos;

public partial class ProcessInfo
{
    public static readonly ConcurrentDictionary<int, (string ProcessName, string ProcessPath, string ProcessCommandLine)> _cache = new();
    private static readonly ConcurrentQueue<int> _cacheQueue = new();
    private const int CacheSize = 1024;
    public const string ICON_DEFAULT_PROCESS = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAJGSURBVFhH7ZfbThNRGIV71fPBtryCXhpfS9Sqbe0BFKsIKh5auCDhyqTPIUilIOVUW4paQUx8jN4s8/8zezrsn53OhaYksJMvnczF+tbac1Wf7+pc+lMuZqvlYh7jIVv1yZf/nmazee4vwQUGg8FYuHgF6vU6lpeXGXpW7299+IOJpd+YWDpFevEU6dovpGsnSFeJY6TeHyP17idSb4k+km/6uLlyMjJXFDCRXiThUMpCR9p3pMmF70i+HqLn6HgvcO7KH0guELbw1TdcI14eMYn5nsjREQVMV6WWWisN0vkjJOYOLV4Q3ZG5ooCJ4dUqoZL2XMJDJGa7SMx2EH/eQfzZV5Gj47nAcGXPYq7nEnZZmGBpB/FKG7GnxIHI0REFTFelX23ctZJxpG3EZg4Qe7LPjMoVBUy4lwopCWf2mejjPZtdRKd3RY6O5wKOsNJG3JGqpXssU0SmdhAp7yBSaokcHVHAdFXupVES0kolZWHLotRCpLiNcOELowt1RAETtFRda3RKrbSFLLWE4cIWwo+2EM5vMnqOjucCtPLMUlqppCS0CeWaCGWJDUbP0REFTJ8gUrKEzlIlzW8ilCNs6cMNBB98trjfEEIdUcCEkobsq3WELFVCSxrMrCNwj/gkcnS8FyCxLQ3SSkfaQCCzjmCmwULm7hoCd9YQmFwVOTqigOkT8NVqUhazUElX4Z8kPsJ/20IX6ogCJm5Utq2VmbMr/SwdCt1cn26KHB3PBf4XF6NAqZCr0cM4KBXyNf1vwtW5fOcvKPlRePbRP+UAAAAASUVORK5CYII=";
    public const string ICON_WINDAUBEFIREWALL = "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";
    public const string ICON_UNKNOWN = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAfFJREFUWEfFlztOw0AQhn9HS4QgIK6CRE8KNzQ+AQU34CocAa4QUVCkSJWCiqMgBEKKogStsVezk92Z9UDA5cr2P49vHlsBqABs8f1U0+n0eLFYfPzVmRfvn6qu69P5fP5Gxfd91hvwL+I+4t4Aq/g9gMvxeLxcrVbXlqg1TTPxOZ/wnKfC7pzbrNdrkjHAOYfM2ajUoDYCystbQUgy6BFAozGkQWgVbw3rDBejIUH4G+KhwnKs5SDUxFOGPwO4IJ5H6anr+oyXeA5CSVyFS4F1x/AdCIUfqOIEuE3vPgN4J+IRhIL4EYDPvl1rZHfvJSPJU8FD8koTR6x/B3DCQApepvJbGkkakpx4sIkIpUJc6swDgBvvDIcwlzda07nGk6oK6X+jPo0UwnYkG7perpdk/0dTRiHUaj943xl5DuAlA6bmTKioYP3AYdMuL0bx6NtBEJL0DM05T22r+xMIUy1cCzsFOAnhoW82Bgg5G9rOEMT9GlDaCbXBcuecuy1ZWKydkHuZmgtqI0vtB9ZcWiGMDLeMY2nB0CC8AvDESze3E2rhjECSpp9SujGEbMxqHmm009rPrn7ixcTQHTmsfo8/kPaI0ouJJRrqBjXoYtKlR2MDqeVE2qBKLibWq1s7dLT1LeqEPiSz2cyvX+G6vu+zL7EDTSSNIbkhAAAAAElFTkSuQmCC";

    private static readonly uint[] _accessRights = [
        0x001F0FFF,             // PROCESS_ALL_ACCESS
        0x0410,                  // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        0x0400,                 // PROCESS_QUERY_INFORMATION
        0x1000                 // PROCESS_QUERY_LIMITED_INFORMATION
    ];

    private static void AddToCache(int pid, string processName, string? processPath = null, string? processCommandLine = null)
    {
        _cache.TryAdd(pid, (processName, processPath ?? "", processCommandLine ?? ""));
        _cacheQueue.Enqueue(pid);

        // Cleanup old entries if cache is too large
        while (_cache.Count > CacheSize && _cacheQueue.TryDequeue(out var oldestPid))
        {
            _cache.TryRemove(oldestPid, out _);
        }

        // Cleanup entries for processes that no longer exist
        var processIds = Process.GetProcesses().Select(p => p.Id).ToArray();
        foreach (var cachedPid in _cache.Keys.ToArray())
        {
            if (!processIds.Contains(cachedPid))
            {
                _cache.TryRemove(cachedPid, out _);
            }
        }
    }

    public static string GetProcessIconBase64(string filePath)
    {
        try
        {
            if (filePath == "UNKNOWN" ||
            filePath == "SYSTEM" ||
            filePath == null ||
            !File.Exists(filePath))
                return ICON_DEFAULT_PROCESS;

            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(filePath);
            if (icon == null) return ICON_DEFAULT_PROCESS;
            using var ms = new MemoryStream();
            using var bitmap = icon.ToBitmap();
            bitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
            return Convert.ToBase64String(ms.ToArray());
        }
        catch
        {
            return ICON_DEFAULT_PROCESS;
        }
    }

    public static (string name, string path, string commandline) GetProcessInfo(int pid)
    {
        if (pid == 0 || pid == 4) return ("SYSTEM", "SYSTEM", "SYSTEM");

        // Try cache first
        if (_cache.TryGetValue(pid, out var cachedInfo))
        {
            return (cachedInfo.ProcessName, cachedInfo.ProcessPath, cachedInfo.ProcessCommandLine);
        }

        var name = "UNKNOWN";
        var path = "UNKNOWN";
        var commandline = "UNKNOWN";

        try
        {
            // Try P/Invoke first (fastest method)
            foreach (var access in _accessRights)
            {
                using var process = GetProcessHandle(pid, access);
                if (process.Handle != IntPtr.Zero)
                {
                    path = GetProcessPathViaHandle(process.Handle);
                    if (!string.IsNullOrEmpty(path) && path != "UNKNOWN")
                    {
                        name = Path.GetFileNameWithoutExtension(path);
                        commandline = GetProcessCommandLine(process.Handle);
                        break;
                    }
                }
            }

            // If P/Invoke failed, try WMI
            if (path == "UNKNOWN")
            {
                var wmiInfo = GetProcessWMIInfos(pid);
                name = string.IsNullOrEmpty(wmiInfo.name) ? name : wmiInfo.name;
                path = string.IsNullOrEmpty(wmiInfo.path) ? path : wmiInfo.path;
                commandline = string.IsNullOrEmpty(wmiInfo.commandline) ? commandline : wmiInfo.commandline;
            }

            // Special case handling
            if (IsWindowsServiceProcess(path) || IsWindowsServiceProcessByName(name))
            {
                var serviceName = GetServiceName(pid);
                if (!string.IsNullOrEmpty(serviceName))
                {
                    name = serviceName;
                    path = @"C:\Windows\System32\svchost.exe";
                }
            }
            else if (IsWinStoreApp(path))
            {
                name = GetWinStoreApp(path);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error getting process info for PID {pid}: {ex.Message}");
        }

        AddToCache(pid, name, path, commandline);
        return (name, path, commandline);
    }

    private static ProcessHandle GetProcessHandle(int pid, uint accessRights)
    {
        var handle = OpenProcess(accessRights, false, (uint)pid);
        return new ProcessHandle(handle);
    }

    private static string GetProcessPathViaHandle(IntPtr handle)
    {
        var buffer = new char[1024];
        int size = buffer.Length;

        unsafe
        {
            fixed (char* ptr = buffer)
            {
                if (QueryFullProcessImageName(handle, 0, ptr, ref size))
                {
                    return new string(buffer, 0, size);
                }
            }
        }

        // If QueryFullProcessImageName fails, try both GetModuleFileNameEx versions as fallback
        unsafe
        {
            fixed (char* ptr = buffer)
            {
                // Try psapi.dll version
                uint result = GetModuleFileNameEx(handle, IntPtr.Zero, ptr, (uint)buffer.Length);
                if (result > 0)
                {
                    return new string(buffer, 0, (int)result);
                }

                // Try kernel32.dll version
                result = K32GetModuleFileNameEx(handle, IntPtr.Zero, ptr, (uint)buffer.Length);
                if (result > 0)
                {
                    return new string(buffer, 0, (int)result);
                }
            }
        }

        return "UNKNOWN";
    }

    private readonly struct ProcessHandle : IDisposable
    {
        public IntPtr Handle { get; }
        public ProcessHandle(IntPtr handle) => Handle = handle;
        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
                CloseHandle(Handle);
        }
    }

    private static (string name, string path, string commandline) GetProcessInfoPInvokes(int pid)
    {
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        // Try different combinations of access rights
        uint[] accessRights = [
            PROCESS_QUERY_LIMITED_INFORMATION,                    // Try most limited access first
            PROCESS_QUERY_INFORMATION,                           // Then try more access
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,         // Then try with VM read
            0x001F0FFF                                          // Finally try PROCESS_ALL_ACCESS
        ];

        IntPtr hProcess = IntPtr.Zero;
        string path = "";
        string name = "";
        string commandline = "";

        foreach (var access in accessRights)
        {
            hProcess = OpenProcess(access, false, (uint)pid);
            if (hProcess == IntPtr.Zero) continue;

            try
            {
                // First try with QueryFullProcessImageName
                char[] exePath = new char[1024];
                int size = exePath.Length;
                unsafe
                {
                    fixed (char* pExePath = exePath)
                    {
                        if (QueryFullProcessImageName(hProcess, 0, pExePath, ref size))
                        {
                            path = new string(exePath, 0, size);
                            name = Path.GetFileNameWithoutExtension(path);

                            // Only try to get command line if we have VM_READ access
                            if ((access & PROCESS_VM_READ) != 0)
                            {
                                commandline = GetProcessCommandLine(hProcess);
                            }

                            if (!string.IsNullOrEmpty(path)) break;
                        }
                    }
                }

                // Fallback to GetModuleFileNameEx if QueryFullProcessImageName failed
                if (string.IsNullOrEmpty(path))
                {
                    unsafe
                    {
                        fixed (char* pExePath = exePath)
                        {
                            uint result = GetModuleFileNameEx(hProcess, IntPtr.Zero, pExePath, (uint)exePath.Length);
                            if (result > 0)
                            {
                                path = new string(exePath, 0, (int)result);
                                name = Path.GetFileNameWithoutExtension(path);

                                // Only try to get command line if we have VM_READ access
                                if ((access & PROCESS_VM_READ) != 0)
                                {
                                    commandline = GetProcessCommandLine(hProcess);
                                }

                                if (!string.IsNullOrEmpty(path)) break;
                            }
                        }
                    }
                }

                // If we failed to get the path with current access rights
                if (string.IsNullOrEmpty(path))
                {
                    Debug.WriteLine($"GetProcessInfoPInvokes: Failed to get path for PID {pid} with access rights 0x{access:X}");
                }
                else
                {
                    break; // Path found, exit the loop
                }
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                    CloseHandle(hProcess);
            }

            // If we got the path, no need to try other access rights
            if (!string.IsNullOrEmpty(path)) break;
        }

        // After all attempts, if path is still empty
        if (string.IsNullOrEmpty(path))
        {
            Debug.WriteLine($"GetProcessInfoPInvokes: Could not get path for PID {pid} after all attempts.");
        }

        return (name, path, commandline);
    }

    private static string GetProcessCommandLine(IntPtr hProcess)
    {
        // Get PROCESS_BASIC_INFORMATION
        PROCESS_BASIC_INFORMATION pbi = new();
        uint returnLength = 0;
        int status = NtQueryInformationProcess(hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), ref returnLength);
        if (status != 0)
        {
            return "";
        }

        // Adjust offsets for 64-bit architecture
        IntPtr pebAddress = pbi.PebBaseAddress;
        IntPtr processParametersAddress;
        byte[] addrBuffer = new byte[IntPtr.Size];

        // For 64-bit processes, use offset 0x20 for ProcessParameters
        if (!ReadProcessMemory(hProcess, pebAddress + 0x20, addrBuffer, addrBuffer.Length, out _))
        {
            return "";
        }
        processParametersAddress = (IntPtr)BitConverter.ToInt64(addrBuffer, 0);

        // Read CommandLine UNICODE_STRING
        UNICODE_STRING commandLine;
        byte[] unicodeStringBuffer = new byte[Marshal.SizeOf(typeof(UNICODE_STRING))];

        // For 64-bit processes, use offset 0x70 for CommandLine
        if (!ReadProcessMemory(hProcess, processParametersAddress + 0x70, unicodeStringBuffer, unicodeStringBuffer.Length, out _))
        {
            return "";
        }
        commandLine = ByteArrayToStructure<UNICODE_STRING>(unicodeStringBuffer);

        // Read the actual command line string
        byte[] commandLineBuffer = new byte[commandLine.Length];
        if (!ReadProcessMemory(hProcess, commandLine.Buffer, commandLineBuffer, commandLine.Length, out _))
        {
            return "";
        }
        string commandLineString = Encoding.Unicode.GetString(commandLineBuffer);
        return commandLineString;
    }

    private static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    private static (string name, string path, string commandline) GetProcessWMIInfos(int pid)
    {
        string name = "";
        string path = "";
        string commandline = "";

        try
        {
            string query = $"SELECT Name, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = {pid}";
            using var searcher = new ManagementObjectSearcher(query);
            var results = searcher.Get();
            if (results.Count == 0)
            {
                //Debug.WriteLine($"GetProcessWMIInfos: No WMI info found for PID {pid}");
            }
            else
            {
                foreach (ManagementObject obj in results.Cast<ManagementObject>())
                {
                    // Assign to existing variables instead of redeclaring
                    name = obj["Name"]?.ToString() ?? "";
                    path = obj["ExecutablePath"]?.ToString() ?? "";
                    commandline = obj["CommandLine"]?.ToString() ?? "";
                    return (name, path, commandline);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"GetProcessWMIInfos: Exception for PID {pid}: {ex.Message}");
        }

        // If path is still empty
        if (string.IsNullOrEmpty(path))
        {
            //Debug.WriteLine($"GetProcessWMIInfos: Path not found for PID {pid}");
        }

        return (name, path, commandline);
    }

    private static string GetProcessProcessName(int pid)
    {
        try
        {
            string query = $"SELECT Name FROM Win32_Process WHERE ProcessId = {pid}";
            using var searcher = new ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                return obj["Name"]?.ToString() ?? "";
            }
        }
        catch (Exception)
        {
            return "";
        }
        return "";
    }

    private static string GetProcessWMIPath(int pid)
    {
        try
        {
            string query = $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}";
            using var searcher = new ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                return obj["ExecutablePath"]?.ToString() ?? "";
            }
        }
        catch (Exception)
        {
            return "";
        }
        return "";
    }

    private static string GetProcessWMICommandLine(int pid)
    {
        try
        {
            string query = $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}";
            using var searcher = new ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString() ?? "";
            }
        }
        catch (Exception)
        {
            return "";
        }
        return "";
    }

    private static bool IsWindowsServiceProcess(string path)
    {
        return path.Equals(@"C:\Windows\System32\svchost.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWindowsServiceProcessByName(string name)
    {
        return name.Equals(@"svchost.exe", StringComparison.OrdinalIgnoreCase) ||
        name.Equals(@"svchost", StringComparison.OrdinalIgnoreCase);
    }
    private static bool IsWinStoreApp(string path)
    {
        return path.StartsWith(@"C:\Program Files\WindowsApps\");
    }
    private static string GetWinStoreApp(string path)
    {
        return "WinStore:" + Path.GetFileName(path);
    }

    public static string GetProcessName(int pid)
    {
        if (_cache.TryGetValue(pid, out var cachedData))
        {
            return cachedData.ProcessName;
        }
        return GetProcessInfo(pid).name;
    }

    public static string GetProcessPath(int pid)
    {
        if (_cache.TryGetValue(pid, out var cachedData))
        {
            return cachedData.ProcessPath;
        }
        return GetProcessInfo(pid).path;
    }

    private static string GetServiceName(int pid)
    {
        var services = new List<string>();
        try
        {
            string query = $"SELECT Name FROM Win32_Service WHERE ProcessId = {pid}";
            using var searcher = new ManagementObjectSearcher(query);
            foreach (var obj in searcher.Get())
            {
                var name = obj["Name"]?.ToString();
                if (!string.IsNullOrEmpty(name))
                {
                    services.Add($"SVC:{name}");
                }
            }
        }
        catch (Exception)
        {
            Debug.WriteLine("Error getting service name for PID: " + pid);
            throw;
        }

        return services.Count > 0 ? string.Join(", ", services) : "";
    }

    private static string GetProcessPathFromWMIOwner(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");

            foreach (ManagementObject process in searcher.Get().Cast<ManagementObject>())
            {
                string[] ownerInfo = new string[2];
                process.InvokeMethod("GetOwner", ownerInfo);
                string userName = ownerInfo[0] ?? "";
                string domain = ownerInfo[1] ?? "";

                if (!string.IsNullOrEmpty(userName))
                {
                    // Try to find the process in the user's common folders
                    var commonPaths = new[] {
                        $@"C:\Users\{userName}\AppData\Local",
                        $@"C:\Users\{userName}\AppData\Roaming",
                        $@"C:\Users\{userName}\AppData\Local\Programs",
                    };

                    var processName = process["Name"]?.ToString();
                    if (string.IsNullOrEmpty(processName)) continue;

                    foreach (var basePath in commonPaths)
                    {
                        if (!Directory.Exists(basePath)) continue;

                        var files = Directory.GetFiles(basePath, processName, SearchOption.AllDirectories);
                        if (files.Length > 0) return files[0];
                    }
                }
            }
        }
        catch { }
        return "";
    }

    private static string GetProcessImageFileNamePath(IntPtr hProcess)
    {
        try
        {
            char[] path = new char[1024];
            unsafe
            {
                fixed (char* pPath = path)
                {
                    uint result = GetProcessImageFileName(hProcess, pPath, (uint)path.Length);
                    if (result > 0)
                    {
                        // Convert device path to regular path
                        string devicePath = new string(path, 0, (int)result);
                        foreach (var drive in DriveInfo.GetDrives())
                        {
                            if (string.IsNullOrEmpty(drive.Name)) continue;

                            var deviceName = GetDeviceName(drive.Name.TrimEnd('\\'));
                            if (string.IsNullOrEmpty(deviceName)) continue;

                            if (devicePath.StartsWith(deviceName))
                            {
                                return devicePath.Replace(deviceName, drive.Name.TrimEnd('\\'));
                            }
                        }
                        return devicePath;
                    }
                }
            }
        }
        catch { }
        return "";
    }

    private static string GetDeviceName(string drivePath)
    {
        char[] targetPath = new char[512];
        uint result = QueryDosDevice(drivePath, targetPath, targetPath.Length);
        if (result > 0)
        {
            return new string(targetPath, 0, (int)result);
        }
        return "";
    }

    // P/Invoke signatures
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        uint dwProcessId);

    [LibraryImport("psapi.dll", EntryPoint = "GetModuleFileNameExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint GetModuleFileNameEx(
        IntPtr hProcess,
        IntPtr hModule,
        char* lpFilename,
        uint nSize);

    [LibraryImport("kernel32.dll", EntryPoint = "K32GetModuleFileNameExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint K32GetModuleFileNameEx(
        IntPtr hProcess,
        IntPtr hModule,
        char* lpFilename,
        uint nSize);

    [LibraryImport("psapi.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint GetProcessImageFileName(
        IntPtr hProcess,
        char* lpImageFileName,
        uint nSize);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint QueryDosDevice(
        string lpDeviceName,
        char[] lpTargetPath,
        int ucchMax);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(
        IntPtr hProcess,
        uint dwFlags,
        char* lpExeName,
        ref int lpdwSize);

    [LibraryImport("ntdll.dll", SetLastError = true)]
    private static partial int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        uint processInformationLength,
        ref uint returnLength);

    [LibraryImport("shell32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr ExtractIcon(
        IntPtr hInst,
        string lpszExeFileName,
        int nIconIndex);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr hObject);

    // Structures
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;

    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
}
