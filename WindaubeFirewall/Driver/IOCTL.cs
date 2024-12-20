using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WindaubeFirewall.Driver;

public partial class IOCTL
{
    private const uint SIOCTL_TYPE = 40000;
    private const uint METHOD_BUFFERED = 0;
    private const uint FILE_READ_DATA = 0x0001;
    private const uint FILE_WRITE_DATA = 0x0002;

    public static readonly uint CODE_VERSION = CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);
    public static readonly uint CODE_SHUTDOWN = CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

    /// <summary>
    /// Retrieves the version information from the driver.
    /// </summary>
    /// <param name="safeFileHandle">Handle to the driver device</param>
    /// <returns>Version string in format "x.x.x.x"</returns>
    public static string GetVersion(SafeFileHandle safeFileHandle)
    {
        if (safeFileHandle == null || safeFileHandle.IsInvalid)
        {
            throw new InvalidOperationException("Device handle is null or invalid");
        }
        byte[] inBuffer = new byte[4];
        uint bytesReturned = DeviceIoControlSync(safeFileHandle, CODE_VERSION, null, inBuffer);
        if (bytesReturned == 0)
        {
            throw new InvalidOperationException("No bytes returned from IOCTL_VERSION");
        }
        return $"{inBuffer[0]}.{inBuffer[1]}.{inBuffer[2]}.{inBuffer[3]}";
    }

    /// <summary>
    /// Sends shutdown command to the driver.
    /// </summary>
    /// <param name="safeFileHandle">Handle to the driver device</param>
    public static void Shutdown(SafeFileHandle safeFileHandle)
    {
        if (safeFileHandle == null || safeFileHandle.IsInvalid)
        {
            throw new InvalidOperationException("Device handle is null or invalid");
        }
        DeviceIoControlSync(safeFileHandle, CODE_SHUTDOWN, null, null);
    }

    /// <summary>
    /// Creates an IOCTL control code.
    /// </summary>
    /// <returns>The computed control code</returns>
    public static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
    {
        return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method;
    }

    /// <summary>
    /// Performs a synchronous IO control operation with the driver.
    /// </summary>
    /// <returns>Number of bytes returned from the operation</returns>
    public static uint DeviceIoControlSync(SafeFileHandle hDevice, uint ioControlCode, byte[]? inBuffer, byte[]? outBuffer)
    {
        IntPtr inBufferPtr = IntPtr.Zero;
        IntPtr outBufferPtr = IntPtr.Zero;
        GCHandle inHandle = default;
        GCHandle outHandle = default;
        uint bytesReturned = 0;
        try
        {
            if (inBuffer != null && inBuffer.Length > 0)
            {
                inHandle = GCHandle.Alloc(inBuffer, GCHandleType.Pinned);
                inBufferPtr = inHandle.AddrOfPinnedObject();
            }
            if (outBuffer != null && outBuffer.Length > 0)
            {
                outHandle = GCHandle.Alloc(outBuffer, GCHandleType.Pinned);
                outBufferPtr = outHandle.AddrOfPinnedObject();
            }
            bool result = DeviceIoControl(hDevice, ioControlCode, inBufferPtr, (uint)(inBuffer?.Length ?? 0), outBufferPtr, (uint)(outBuffer?.Length ?? 0), ref bytesReturned, IntPtr.Zero);
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            if (inHandle.IsAllocated) { inHandle.Free(); }
            if (outHandle.IsAllocated) { outHandle.Free(); }
        }
        return bytesReturned;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeFileHandle CreateFile(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        ref uint lpBytesReturned,
        IntPtr lpOverlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetOverlappedResult(
        SafeFileHandle hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool bWait);
}
