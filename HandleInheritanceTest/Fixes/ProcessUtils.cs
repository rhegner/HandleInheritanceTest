using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace HandleInheritanceTest.Fixes
{
	public class ProcessUtils
	{

		public static unsafe void StartProcess(string executable, string arguments, string workingDirectory = null, bool inheritHandles = true)
		{
			var commandLine = BuildCommandLine(executable, arguments);

			var unused_SecAttrs = new SECURITY_ATTRIBUTES();

			int creationFlags = 0;

			if (string.IsNullOrEmpty(workingDirectory))
				workingDirectory = Directory.GetCurrentDirectory();

			var startupInfo = new STARTUPINFO();
			startupInfo.cb = sizeof(STARTUPINFO);

			var processInfo = new PROCESS_INFORMATION();

			try
			{

				int errorCode = 0;
				var retVal = CreateProcess(
					null,                // we don't need this since all the info is in commandLine
					commandLine,         // pointer to the command line string
					ref unused_SecAttrs, // address to process security attributes, we don't need to inherit the handle
					ref unused_SecAttrs, // address to thread security attributes.
					inheritHandles,      // handle inheritance flag
					creationFlags,       // creation flags
					IntPtr.Zero,         // pointer to new environment block
					workingDirectory,    // pointer to current directory name
					ref startupInfo,     // pointer to STARTUPINFO
					ref processInfo      // pointer to PROCESS_INFORMATION
				);
				if (!retVal)
				{
					errorCode = Marshal.GetLastWin32Error();
					throw new Win32Exception(errorCode);
				}
			}
			finally
			{
				MyCloseHandle(startupInfo.hStdError);
				MyCloseHandle(startupInfo.hStdInput);
				MyCloseHandle(startupInfo.hStdOutput);
				MyCloseHandle(processInfo.hThread);
				MyCloseHandle(processInfo.hProcess);
			}
		}

		private static void MyCloseHandle(IntPtr handle)
		{
			if (handle != IntPtr.Zero && handle != new IntPtr(-1))
				CloseHandle(handle);
		}

		private static StringBuilder BuildCommandLine(string executableFileName, string arguments)
		{
			// Construct a StringBuilder with the appropriate command line
			// to pass to CreateProcess.  If the filename isn't already 
			// in quotes, we quote it here.  This prevents some security
			// problems (it specifies exactly which part of the string
			// is the file to execute).
			StringBuilder commandLine = new StringBuilder();
			string fileName = executableFileName.Trim();
			bool fileNameIsQuoted = (fileName.StartsWith("\"", StringComparison.Ordinal) && fileName.EndsWith("\"", StringComparison.Ordinal));
			if (!fileNameIsQuoted)
			{
				commandLine.Append("\"");
			}

			commandLine.Append(fileName);

			if (!fileNameIsQuoted)
			{
				commandLine.Append("\"");
			}

			if (!string.IsNullOrEmpty(arguments))
			{
				commandLine.Append(" ");
				commandLine.Append(arguments);
			}

			return commandLine;
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, BestFitMapping = false, EntryPoint = "CreateProcessW")]
		private static extern bool CreateProcess(
			string lpApplicationName,
			StringBuilder lpCommandLine,
			ref SECURITY_ATTRIBUTES procSecAttrs,
			ref SECURITY_ATTRIBUTES threadSecAttrs,
			bool bInheritHandles,
			int dwCreationFlags,
			IntPtr lpEnvironment,
			string lpCurrentDirectory,
			ref STARTUPINFO lpStartupInfo,
			ref PROCESS_INFORMATION lpProcessInformation
		);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CloseHandle(IntPtr handle);

		private enum BOOL : int
		{
			FALSE = 0,
			TRUE = 1,
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct SECURITY_ATTRIBUTES
		{
			internal uint nLength;
			internal IntPtr lpSecurityDescriptor;
			internal BOOL bInheritHandle;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PROCESS_INFORMATION
		{
			internal IntPtr hProcess;
			internal IntPtr hThread;
			internal int dwProcessId;
			internal int dwThreadId;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct STARTUPINFO
		{
			internal int cb;
			internal IntPtr lpReserved;
			internal IntPtr lpDesktop;
			internal IntPtr lpTitle;
			internal int dwX;
			internal int dwY;
			internal int dwXSize;
			internal int dwYSize;
			internal int dwXCountChars;
			internal int dwYCountChars;
			internal int dwFillAttribute;
			internal int dwFlags;
			internal short wShowWindow;
			internal short cbReserved2;
			internal IntPtr lpReserved2;
			internal IntPtr hStdInput;
			internal IntPtr hStdOutput;
			internal IntPtr hStdError;
		}

	}
}
