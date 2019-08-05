using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace HandleInheritanceTest
{
	public class Program
	{
		public static async Task Main(string[] args)
		{
			try
			{
				if (args.Length < 3)
					throw new Exception("Please provide at least three arguments: Role [Parent|Child], Port, Mode [NoFix|CloseInheritedSockets]");

				var role = args[0];
				if (role != "Parent" && role != "Child")
					throw new Exception("Role must be either Parent or Child");

				var port = int.Parse(args[1]);

				var mode = args[2];
				if (mode != "NoFix" && mode != "CloseInheritedSockets")
					throw new Exception("Mode must be NoFix or CloseInheritedSockets");

				int parentPid = 0;
				if (role == "Child")
				{
					if (args.Length < 4)
						throw new Exception("Please provide a fourth argument Pid for Child role");
					parentPid = int.Parse(args[3]);
				}

				var binPath = typeof(Program).GetTypeInfo().Assembly.Location;
				var pid = Process.GetCurrentProcess().Id;

				LogInfo(role, $"Started from {binPath}");
				LogInfo(role, $"Port: {port}");
				LogInfo(role, $"Mode: {mode}");
				LogInfo(role, $"Pid:  {pid}");
				if (parentPid > 0)
					LogInfo(role, $"PPid: {parentPid}");

				if (role == "Child")
				{
					if (mode == "CloseInheritedSockets")
					{
						LogInfo(role, $"Closing inherited sockets...");
						LogInfo(role, $"This fix does not work yet. Listing all open handles with name and type instead:");
						var handles = Fixes.HandlersUtils.GetSystemHandles();
						foreach (var h in handles)
							LogInfo(role, $"{h.Type} - {h.Name}");
						LogInfo(role, "End of List!");
					}

					LogInfo(role, $"Waiting for parent process to exit...");
					using (var process = Process.GetProcessById(parentPid))
					{
						process.Kill();
						if (!process.WaitForExit(5000))
							throw new Exception("The process did not exit within the specified timeout!");
					}
					LogInfo(role, "Waiting for 2 seconds before initializing web host");
					await Task.Delay(TimeSpan.FromSeconds(2));
				}

				LogInfo(role, "Building web host...");
				var webHost = CreateWebHostBuilder(args, port).Build();

				LogInfo(role, "Starting web host...");
				var webHostCts = new CancellationTokenSource();
				var webHostTask = webHost.StartAsync(webHostCts.Token);

				if (role == "Parent")
				{

					LogInfo(role, "Waiting for 5 seconds...");
					await Task.Delay(TimeSpan.FromSeconds(5));

					LogInfo(role, "Starting child process...");
					var arguments = $"\"{binPath}\" Child {port} {mode} {pid}";
					using (var process = Process.Start("dotnet", arguments)) { }

					LogInfo(role, "Shutting down web host...");
					webHostCts.Cancel();
					await webHostTask;

					LogInfo(role, "Waiting for 5 seconds...");
					await Task.Delay(TimeSpan.FromSeconds(5));
				}
				else
				{
					await webHostTask;
				}


			}
			catch (Exception ex)
			{
				Console.WriteLine("An error occurred:");
				Console.WriteLine(ex.Message);
			}
		}

		private static void LogInfo(string role, string message)
			=> Console.WriteLine($"{role}: {message}");

		public static IWebHostBuilder CreateWebHostBuilder(string[] args, int port) =>
			WebHost.CreateDefaultBuilder(args)
				.UseUrls($"http://*:{port}")
				.UseStartup<Startup>();
	}
}
