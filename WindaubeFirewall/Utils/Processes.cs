namespace WindaubeFirewall.Utils;

public static class Processes
{
    public static int ExecuteProgram(string program, string arguments, int timeoutMs = 30000)
    {
        using var process = new System.Diagnostics.Process();
        process.StartInfo.FileName = program;
        process.StartInfo.Arguments = arguments;
        process.StartInfo.Verb = "runas";
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        try
        {
            process.Start();

            if (!process.WaitForExit(timeoutMs))
            {
                process.Kill();
                throw new TimeoutException($"Process execution timed out after {timeoutMs}ms");
            }

            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            if (process.ExitCode != 0)
            {
                throw new Exception($"""
                    Process execution failed:
                    Program: {program}
                    Arguments: {arguments}
                    Exit Code: {process.ExitCode}
                    Error: {error}
                    Output: {output}
                    """);
            }

            return process.ExitCode;
        }
        catch (Exception ex) when (ex is not TimeoutException)
        {
            throw new Exception($"Failed to execute program: {program}", ex);
        }
    }
}
