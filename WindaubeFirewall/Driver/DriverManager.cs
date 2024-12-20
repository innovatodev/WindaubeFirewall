using System.IO;
using System.ServiceProcess;

namespace WindaubeFirewall.Driver;

public class DriverManager
{
    private static readonly string _kextPath = Constants.KextPath;
    private static readonly string _kextName = Constants.KextName;

    /// <summary>
    /// Performs cleanup operations for the driver, including stopping and uninstalling if necessary.
    /// </summary>
    public static void CleanDriver()
    {
        if (!IsDriverInstalled() && !IsDriverRunning()) { return; }
        Logger.Log("Cleaning driver...");
        DriverWorker.KextBinaryReader?.Dispose();
        DriverWorker.KextBinaryReader = null;
        DriverWorker.KextBinaryWriter?.Dispose();
        DriverWorker.KextBinaryWriter = null;
        DriverWorker.KextFileStreamReader?.Dispose();
        DriverWorker.KextFileStreamWriter?.Dispose();
        DriverWorker.KextFileStreamWriter = null;
        DriverWorker.KextFileStreamReader = null;
        DriverWorker.KextFileHandle?.Dispose();
        DriverWorker.KextFileHandle = null;
        UninstallDriver();
    }

    /// <summary>
    /// Installs the driver if it's not already installed. Throws if driver file is not found.
    /// </summary>
    public static void InstallDriver()
    {
        if (IsDriverInstalled()) { return; }
        if (!File.Exists(_kextPath))
        {
            throw new FileNotFoundException("Driver file not found", _kextPath);
        }

        Logger.Log("Installing driver...");
        Processes.ExecuteProgram("sc", $"create {_kextName} binPath= \"{_kextPath}\" type= kernel start= demand");
        Logger.Log($"{Constants.KextName} driver installed successfully.");
    }

    /// <summary>
    /// Uninstalls the driver if it's installed, stopping it first if necessary.
    /// </summary>
    public static void UninstallDriver()
    {
        if (!IsDriverInstalled()) { return; }
        Logger.Log("Uninstalling driver...");
        if (IsDriverRunning())
        {
            StopDriver();
        }
        Processes.ExecuteProgram("sc", $"delete {_kextName}");
        Logger.Log($"{Constants.KextName} driver uninstalled successfully.");
    }

    /// <summary>
    /// Starts the driver service. Throws if driver is not installed.
    /// </summary>
    public static void StartDriver()
    {
        if (!IsDriverInstalled())
        {
            throw new InvalidOperationException("Driver is not installed");
        }
        using ServiceController serviceController = new(Constants.KextName);
        if (GetStatus() != ServiceControllerStatus.Running)
        {
            Logger.Log("Starting Driver...");
            serviceController.Start();
            serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            Logger.Log($"{Constants.KextName} driver started successfully.");
        }
    }

    /// <summary>
    /// Stops the driver service if it's running.
    /// </summary>
    public static void StopDriver()
    {
        if (!IsDriverRunning())
        {
            return;
        }
        using ServiceController serviceController = new(Constants.KextName);
        if (GetStatus() != ServiceControllerStatus.Stopped)
        {
            Logger.Log("Stopping Driver...");
            serviceController.Stop();
            serviceController.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            Logger.Log($"{Constants.KextName} driver stopped successfully.");
        }
    }

    /// <summary>
    /// Checks if the driver is currently installed in the system.
    /// </summary>
    /// <returns>True if the driver is installed, false otherwise</returns>
    public static bool IsDriverInstalled()
    {
        var services = ServiceController.GetDevices();
        var service = services.FirstOrDefault(s => s.ServiceName.Equals(Constants.KextName, StringComparison.OrdinalIgnoreCase));
        if (service != null)
        {
            return true;
        }
        return false;
    }

    /// <summary>
    /// Checks if the driver service is currently running.
    /// </summary>
    /// <returns>True if the driver is running, false otherwise</returns>
    public static bool IsDriverRunning()
    {
        var services = ServiceController.GetDevices();
        var service = services.FirstOrDefault(s => s.ServiceName.Equals(Constants.KextName, StringComparison.OrdinalIgnoreCase));
        if (service != null && service.Status == ServiceControllerStatus.Running)
        {
            return true;
        }
        return false;
    }

    /// <summary>
    /// Gets the current status of the driver service.
    /// </summary>
    /// <returns>The current ServiceControllerStatus of the driver</returns>
    public static ServiceControllerStatus GetStatus()
    {
        using ServiceController serviceController = new(Constants.KextName);
        return serviceController.Status;
    }

}
