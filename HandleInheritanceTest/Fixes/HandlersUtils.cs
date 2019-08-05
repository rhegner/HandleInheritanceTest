using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HandleInheritanceTest.Fixes
{
	public static class HandlersUtils
	{
		// https://gist.github.com/manuc66/eb2bfccc3617b740e01c004949df1bb8
		// https://github.com/michaelknigge/forcedel/blob/master/src/LowLevelHandleHelper.cs
		// https://social.technet.microsoft.com/Forums/en-US/5b78bf61-4a06-4367-bc28-a9cba3c688b5/howto-enumerate-handles?forum=windowsdevelopment
		// http://forums.codeguru.com/showthread.php?176997-Enum-HANDLEs-for-current-process
		// https://blez.wordpress.com/2012/09/17/enumerating-opened-handles-from-a-process/
		// https://www.pinvoke.net/default.aspx/ntdll.ntquerysysteminformation
		// https://stackoverflow.com/questions/16262114/c-get-handle-of-open-sockets-of-a-program

		// http://www.exploit-monday.com/2013/06/undocumented-ntquerysysteminformation.html
		// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
		// https://github.com/andyvand/ProcessHacker/tree/master/1.x/trunk/ProcessHacker.Native/Api


		private enum NT_STATUS
		{
			STATUS_SUCCESS = 0x00000000,
			STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005L),
			STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004L)
		}

		private enum SYSTEM_INFORMATION_CLASS
		{
			SystemHandleInformation = 16
		}

		internal enum OBJECT_INFORMATION_CLASS
		{
			ObjectNameInformation = 1,
			ObjectTypeInformation = 2
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SYSTEM_HANDLE_ENTRY
		{
			//public short UniqueProcessId;
			//public short CreatorBackTraceIndex;
			public int UniqueProcessId;
			public byte ObjectType;
			public byte HandleFlags;
			public short HandleValue;
			public IntPtr ObjectPointer;
			public int AccessMask;
		}

		[DllImport("ntdll.dll")]
		private static extern NT_STATUS NtQuerySystemInformation(
			[In] SYSTEM_INFORMATION_CLASS SystemInformationClass,
			[In] IntPtr SystemInformation,
			[In] int SystemInformationLength,
			[Out] out int ReturnLength);

		[DllImport("ntdll.dll")]
		private static extern NT_STATUS NtQueryObject(
			[In] IntPtr Handle,
			[In] OBJECT_INFORMATION_CLASS ObjectInformationClass,
			[In] IntPtr ObjectInformation,
			[In] int ObjectInformationLength,
			[Out] out int ReturnLength);

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		struct UNICODE_STRING
		{
			public ushort Length;
			public ushort MaximumLength;
			public string Buffer;
		}

		[StructLayout(LayoutKind.Sequential)]
		struct ObjectTypeInformation    // it's the same for ObjectNameInformation
		{
			public UNICODE_STRING Name;
		}

		public class HandleInfo
		{
			public IntPtr Handle;
			public string Type;
			public string Name;
		}


		// NtQueryObject seems to hang for certain accessMasks... Blacklist them here
		private static readonly int[] AccessMaskBlackList = new int[] { 0x120189 };


		public static List<HandleInfo> GetSystemHandles()
		{
			var pid = Process.GetCurrentProcess().Id;


			NT_STATUS ret;
			int length = 0x10000;
			// Loop, probing for required memory.


			do
			{
				IntPtr ptr = IntPtr.Zero;
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
					RuntimeHelpers.PrepareConstrainedRegions();
					try { }
					finally
					{
						// CER guarantees that the address of the allocated 
						// memory is actually assigned to ptr if an 
						// asynchronous exception occurs.
						ptr = Marshal.AllocHGlobal(length);
					}
					int returnLength;
					ret = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemHandleInformation, ptr, length, out returnLength);
					if (ret == NT_STATUS.STATUS_INFO_LENGTH_MISMATCH)
					{
						// Round required memory up to the nearest 64KB boundary.
						length = ((returnLength + 0xffff) & ~0xffff);
					}
					else if (ret == NT_STATUS.STATUS_SUCCESS)
					{
						int handleCount = Marshal.ReadInt32(ptr);
						int offset = IntPtr.Size;
						int size = Marshal.SizeOf(typeof(SYSTEM_HANDLE_ENTRY));
						var result = new List<HandleInfo>();
						for (int i = 0; i < handleCount; i++)
						{
							SYSTEM_HANDLE_ENTRY handleEntry = (SYSTEM_HANDLE_ENTRY)Marshal.PtrToStructure(ptr + offset, typeof(SYSTEM_HANDLE_ENTRY));
							if (handleEntry.UniqueProcessId == pid && !AccessMaskBlackList.Contains(handleEntry.AccessMask))
							{
								// Console.WriteLine($"{handleEntry.AccessMask}");
								var handle = (IntPtr)handleEntry.HandleValue;
								var type = GetHandleTypeNameToken(handle, OBJECT_INFORMATION_CLASS.ObjectTypeInformation);
								var name = GetHandleTypeNameToken(handle, OBJECT_INFORMATION_CLASS.ObjectNameInformation);
								result.Add(new HandleInfo() { Handle = handle, Type = type, Name = name });
							}
							offset += size;
						}
						return result;
					}
				}
				finally
				{
					// CER guarantees that the allocated memory is freed, 
					// if an asynchronous exception occurs. 
					Marshal.FreeHGlobal(ptr);
				}
			}
			while (ret == NT_STATUS.STATUS_INFO_LENGTH_MISMATCH);

			throw new Exception($"NtQuerySystemInformation failed with return code {ret}");
		}

		private static string GetHandleTypeNameToken(IntPtr handle, OBJECT_INFORMATION_CLASS infoClass)
		{
			int length;
			NtQueryObject(handle, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, IntPtr.Zero, 0, out length);
			IntPtr ptr = IntPtr.Zero;
			RuntimeHelpers.PrepareConstrainedRegions();
			try
			{
				RuntimeHelpers.PrepareConstrainedRegions();
				try { }
				finally
				{
					ptr = Marshal.AllocHGlobal(length);
				}
				var ret = NtQueryObject(handle, infoClass, ptr, length, out length);
				if (ret == NT_STATUS.STATUS_SUCCESS)
				{
					return Marshal.PtrToStructure<ObjectTypeInformation>(ptr).Name.Buffer;
				}
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
			return string.Empty;
		}

	}
}
