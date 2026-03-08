using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Collections.Generic;
using System.Diagnostics;

namespace NetDiagGUI
{
    public partial class MainWindow : Window
    {

        bool dark = true;
        bool running = false;

        public MainWindow()
        {
            InitializeComponent();
            ApplyTheme();
        }

        void Log(string text)
        {
            Dispatcher.Invoke(() =>
            {
                OutputBox.AppendText(text + Environment.NewLine);
                OutputBox.ScrollToEnd();
            });
        }

        void Clear()
        {
            OutputBox.Clear();
        }

        // ---------------- Ping ----------------

        private async void PingButton_Click(object sender, RoutedEventArgs e)
        {
            Clear();

            try
            {
                Ping ping = new Ping();

                var reply = await ping.SendPingAsync(TargetInput.Text);

                Log("Status: " + reply.Status);
                Log("IP: " + reply.Address);
                Log("Time: " + reply.RoundtripTime + " ms");
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
            }
        }

        // ---------------- DNS ----------------

        private void DNSButton_Click(object sender, RoutedEventArgs e)
        {
            Clear();

            try
            {
                var ips = Dns.GetHostAddresses(TargetInput.Text);

                foreach (var ip in ips)
                    Log("IP: " + ip);
            }
            catch (Exception ex)
            {
                Log("DNS Error: " + ex.Message);
            }
        }

        // ---------------- Traceroute ----------------

        private async void TraceButton_Click(object sender, RoutedEventArgs e)
        {
            if (running) return;

            running = true;

            Clear();

            string host = TargetInput.Text;

            Log("Starting traceroute...\n");

            try
            {
                Ping ping = new Ping();

                byte[] buffer = Encoding.ASCII.GetBytes("trace");

                for (int ttl = 1; ttl <= 30; ttl++)
                {
                    PingOptions options = new PingOptions(ttl, true);

                    var reply = await ping.SendPingAsync(host, 4000, buffer, options);

                    if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success)
                        Log($"{ttl}   {reply.Address}");
                    else
                        Log($"{ttl}   *");

                    if (reply.Status == IPStatus.Success)
                        break;
                }
            }
            catch (Exception ex)
            {
                Log("Traceroute error: " + ex.Message);
            }

            running = false;
        }

        // ---------------- WHOIS ----------------

        private async void WhoisButton_Click(object sender, RoutedEventArgs e)
        {
            Clear();

            try
            {
                TcpClient client = new TcpClient("whois.verisign-grs.com", 43);

                var stream = client.GetStream();

                byte[] query = Encoding.ASCII.GetBytes(TargetInput.Text + "\r\n");

                await stream.WriteAsync(query);

                byte[] buffer = new byte[8192];

                int bytes = await stream.ReadAsync(buffer);

                string result = Encoding.ASCII.GetString(buffer, 0, bytes);

                Log(result);

                client.Close();
            }
            catch (Exception ex)
            {
                Log("WHOIS Error: " + ex.Message);
            }
        }

        // ---------------- GeoIP ----------------

        private async void GeoButton_Click(object sender, RoutedEventArgs e)
        {
            Clear();

            try
            {
                WebClient wc = new WebClient();

                string data = await wc.DownloadStringTaskAsync(
                    "http://ip-api.com/json/" + TargetInput.Text);

                Log(data);
            }
            catch (Exception ex)
            {
                Log("GeoIP Error: " + ex.Message);
            }
        }

        // ---------------- Port Scanner ----------------

        private async void ScanPorts_Click(object sender, RoutedEventArgs e)
        {
            if (running) return;

            running = true;

            Clear();

            string host = TargetInput.Text;

            Log("Starting port scan...\n");

            var tasks = new Task[1024];

            for (int port = 1; port <= 1024; port++)
            {
                int p = port;

                tasks[port - 1] = Task.Run(async () =>
                {
                    try
                    {
                        TcpClient client = new TcpClient();

                        var connect = client.ConnectAsync(host, p);

                        if (await Task.WhenAny(connect, Task.Delay(80)) == connect)
                        {
                            if (client.Connected)
                            {
                                Log("OPEN " + p);
                                client.Close();
                            }
                        }
                    }
                    catch { }
                });
            }

            await Task.WhenAll(tasks);

            Log("\nScan finished.");

            running = false;
        }

        // ---------------- LAN Scanner ----------------

        private async void LanScan_Click(object sender, RoutedEventArgs e)
        {
            if (running) return;

            running = true;

            Clear();

            Log("Scanning Local Network...\n");

            string localIP = GetLocalIPAddress();

            string subnet = localIP.Substring(0, localIP.LastIndexOf("."));

            List<string> devices = new List<string>();

            var tasks = new List<Task>();

            for (int i = 1; i < 255; i++)
            {
                string ip = subnet + "." + i;

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        Ping ping = new Ping();

                        var reply = await ping.SendPingAsync(ip, 200);

                        if (reply.Status == IPStatus.Success)
                        {
                            string host = GetHostName(ip);
                            string mac = GetMacAddress(ip);
                            string type = GuessDeviceType(ip);

                            Log($"{ip} | {host} | {mac} | {type}");

                            devices.Add(ip);
                        }
                    }
                    catch { }
                }));
            }

            await Task.WhenAll(tasks);

            Log($"\nTotal Devices: {devices.Count}");

            running = false;
        }

        // ---------------- Helpers ----------------

        string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());

            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                    return ip.ToString();
            }

            return "127.0.0.1";
        }

        string GetHostName(string ip)
        {
            try
            {
                var host = Dns.GetHostEntry(ip);
                return host.HostName;
            }
            catch
            {
                return "Unknown";
            }
        }

        string GetMacAddress(string ip)
        {
            try
            {
                Process p = new Process();
                p.StartInfo.FileName = "arp";
                p.StartInfo.Arguments = "-a " + ip;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.UseShellExecute = false;
                p.Start();

                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();

                foreach (string line in output.Split('\n'))
                {
                    if (line.Contains(ip))
                    {
                        string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                        if (parts.Length >= 2)
                            return parts[1];
                    }
                }
            }
            catch { }

            return "Unknown";
        }

        string GuessDeviceType(string ip)
        {
            if (ip.EndsWith(".1"))
                return "Router";

            return "Device";
        }

        // ---------------- Theme ----------------

        private void ThemeButton_Click(object sender, RoutedEventArgs e)
        {
            dark = !dark;
            ApplyTheme();
        }

        void ApplyTheme()
        {
            if (dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(13, 17, 23));
                OutputBox.Background = Brushes.Black;
                OutputBox.Foreground = Brushes.Lime;
            }
            else
            {
                MainGrid.Background = Brushes.White;
                OutputBox.Background = Brushes.White;
                OutputBox.Foreground = Brushes.Black;
            }
        }

    }
}