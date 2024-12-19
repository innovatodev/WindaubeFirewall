namespace WindaubeFirewall.Utils;

public static class Logger
{
    public static void Log(string message, bool date = false)
    {
        if (date)
        {
            Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff}: {message}");
        }
        else
        {
            Console.WriteLine($"{message}");
        }
    }
}
