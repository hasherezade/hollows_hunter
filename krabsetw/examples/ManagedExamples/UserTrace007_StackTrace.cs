// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates collecting stack traces as part of events.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.O365.Security.ETW;
using Microsoft.Win32.SafeHandles;

namespace ManagedExamples
{
    public static class UserTrace007_StackTrace
    {
        public static void Start()
        {
            if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)))
            {
                Console.WriteLine("Microsoft-Windows-Kernel-* providers can only be traced by Administrators");
                return;
            }

            var trace = new UserTrace("UserTrace007_StackTrace");
            var provider = new Provider("Microsoft-Windows-Kernel-Audit-API-Calls");
            provider.TraceFlags |= TraceFlags.IncludeStackTrace;

            var processFilter = new EventFilter(Filter.EventIdIs(5));  // PsOpenProcess
            processFilter.OnEvent += (record) =>
            {
                var processId = record.ProcessId;
                var targetProcessId = record.GetUInt32("TargetProcessId");
                if (processId == targetProcessId)
                    return; // ignore OpenProcess(*, self)

                var desiredAccess = record.GetUInt32("DesiredAccess");
                if (desiredAccess == (uint)ProcessAccessRights.QUERY_LIMITED_INFORMATION)
                    return; // ignore OpenProcess(QUERY_LIMITED_INFORMATION, *)

                if (0 != record.GetUInt32("ReturnCode"))
                    return; // ignore failures

                var callStack = record.GetStackTrace()
                                .Select(a => a.ToUInt64())
                                .Where(a => a < 0xFFFF000000000000) // skip kernel addresses (for now)
                                .Select(a => MemoryMap.GetClosestSymbol(processId, a));

                Console.WriteLine($"{MemoryMap.GetProcessName(processId)} -> ntoskrnl!PsOpenProcess({ToString(desiredAccess)}, {MemoryMap.GetProcessName(targetProcessId)})\n" +
                                  $"\t[{String.Join(",", callStack)}]");
            };
            provider.AddFilter(processFilter);


            ////////////////////////////////////////////////////////////////////////////////
            // Microsoft-Windows-Kernel-Process
            // These events are used to enrich our call stacks
            var processProvider = new Provider("Microsoft-Windows-Kernel-Process")
            {
                Any = 0x10 | 0x40 // WINEVENT_KEYWORD_PROCESS | WINEVENT_KEYWORD_IMAGE
            };

            // Event 5 - ImageLoad
            var imageLoadFilter = new EventFilter(Filter.EventIdIs(5));
            imageLoadFilter.OnEvent += (record) => {
                var processID = record.GetUInt32("ProcessID");
                var imageBase = BitConverter.ToUInt64(record.GetBinary("ImageBase"), 0); // C# support for Pointer type in krabs?
                var imageSize = BitConverter.ToUInt64(record.GetBinary("ImageSize"), 0);
                var imageName = Path.GetFileNameWithoutExtension(record.GetUnicodeString("ImageName"));
                MemoryMap.AddModule(processID, imageBase, imageSize, imageName);
            };

            // Event 2 - ProcessStop
            var processStopFilter = new EventFilter(Filter.EventIdIs(2));
            processStopFilter.OnEvent += (record) => {
                MemoryMap.RemoveProcess(record.ProcessId);
            };

            processProvider.AddFilter(imageLoadFilter);
            processProvider.AddFilter(processStopFilter);
            trace.Enable(processProvider);
            MemoryMap.Initialise();

            trace.Enable(provider);
            trace.Start();
        }

        enum ProcessAccessRights : uint
        {
            TERMINATE = 0x1,
            CREATE_THREAD = 0x2,
            SET_SESSIONID = 0x4,
            VM_OPERATION = 0x8,
            VM_READ = 0x10,
            VM_WRITE = 0x20,
            DUP_HANDLE = 0x40,
            CREATE_PROCESS = 0x80,
            SET_QUOTA = 0x100,
            SET_INFORMATION = 0x200,
            QUERY_INFORMATION = 0x400,
            SUSPEND_RESUME = 0x800,
            QUERY_LIMITED_INFORMATION = 0x1000,
            DELETE = 0x10000,
            READ_CONTROL = 0x20000,
            WRITE_DAC = 0x40000,
            WRITE_OWNER = 0x80000,
            SYNCHRONIZE = 0x100000
        }

        internal static string ToString(uint desiredAccess)
        {
            if (desiredAccess == 0x1FFFFF)
                return "ALL_ACCESS";

            if (desiredAccess == 0x1F0FFF)
                return "ALL_ACCESS(XP)";

            var rights = new List<string>();
            foreach (uint right in Enum.GetValues(typeof(ProcessAccessRights)))
            {
                if ((desiredAccess & right) == right)
                    rights.Add(Enum.GetName(typeof(ProcessAccessRights), right));
            }
            return string.Join("|", rights);
        }
    }

    /// ETW call stacks are simply a list of return addresses. These can be enriched with module or symbol information after the fact.
    /// You could open a handle to the process and request module or symbol information in the usual fashion.
    /// However, the process may have stopped.
    /// Instead, this class maintains a map of all shared modules and additionally resolves symbols in its own address space.
    /// It assumes normal system behaviour - the presence of security software or malware may invalidate this.
    /// It also assumes a 64KB allocation granularity.
    public class MemoryMap
    {
        // A cache of process names
        private static readonly Dictionary<UInt64, string> _ProcessNameMap = new Dictionary<UInt64, string>();

        // A map of the 64KB regions allocated to shared DLLs
        private static readonly Dictionary<UInt64, string> _SharedDllMap = new Dictionary<UInt64, string>();

        // A per-process map of the 64KB regions allocated to other loaded images.
        // Typically the executable (though this can be shared in special cases) and any DLLs unable to be loaded at the preferred shared address.
        // For example, a trampoline for an inline hook may have been manually allocated in the shared range.
        private static readonly Dictionary<uint, Dictionary<UInt64, string>> _LocalImageMap = new Dictionary<uint, Dictionary<UInt64, string>>();

        // GetCurrentProcess()
        private static readonly SafeProcessHandle CurrentProcess = new SafeProcessHandle(new IntPtr(-1), false);

        // The kernel preferentially uses these two ranges to load DLLs at shared addresses
        // Note - this is not 100% accurate as the WoW64 range only applies to WoW64 processes
        internal static bool IsInSystemImageRange(UInt64 address)
        {
            return ((address >= 0x7FF800000000) && (address < 0x7FFFFFFF0000)) ||  // x64 range
                    ((address >= 0x50000000) && (address < 0x78000000));           // WoW64 range
        }

        public static void Initialise()
        {
            // intialise symbols in the current process
            SymSetOptions(0x800006);  // SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED | SYMOPT_UNDNAME
            if (!SymInitialize(CurrentProcess, null, true))
            {
                throw new ApplicationException($"SymInitialize(CurrentProcess) failed - error=0x{(uint)Marshal.GetLastWin32Error():x}");
            }

            // enumerate loaded modules to pre-populate our maps
            foreach (Process process in Process.GetProcesses())
            {
                uint pid = (uint)process.Id;

                try
                {
                    var imageBase = Convert.ToUInt64(process.MainModule.BaseAddress.ToInt64());
                    var imageSize = Convert.ToUInt64(process.MainModule.ModuleMemorySize);
                    var imageName = Path.GetFileNameWithoutExtension(process.MainModule.ModuleName);

                    _ProcessNameMap[pid] = process.ProcessName;

                    if (!_LocalImageMap.ContainsKey(pid))
                    {
                        _LocalImageMap[pid] = new Dictionary<UInt64, string>();
                    }

                    for (var va = imageBase; va < imageBase + imageSize; va += 64 * 1024)
                    {
                        _LocalImageMap[pid][va] = imageName;
                    }

                    foreach (ProcessModule module in process.Modules)
                    {
                        imageBase = Convert.ToUInt64(module.BaseAddress.ToInt64());
                        imageSize = Convert.ToUInt64(module.ModuleMemorySize);
                        imageName = Path.GetFileNameWithoutExtension(module.ModuleName);
                        if (IsInSystemImageRange(imageBase))
                        {
                            for (var va = imageBase; va < imageBase + imageSize; va += 64 * 1024)
                            {
                                _SharedDllMap[va] = imageName;
                            }
                        }
                        else
                        {
                            for (var va = imageBase; va < imageBase + imageSize; va += 64 * 1024)
                            {
                                _LocalImageMap[pid][va] = imageName;
                            }
                        }
                    }
                }
                catch (Win32Exception) { }             // insufficient privilege
                catch (InvalidOperationException) { }  // process has stopped
            }
        }

        public static void AddModule(uint pid, UInt64 imageBase, UInt64 imageSize, string imageName)
        {
            if (IsInSystemImageRange(imageBase))
            {
                for (var va = imageBase; va < imageBase + imageSize; va += 64 * 1024)
                {
                    _SharedDllMap[va] = imageName;
                }
            }
            else
            {
                // This method of identifying the executable name is not robust :-)
                if (imageName.EndsWith(".exe"))
                {
                    _ProcessNameMap[pid] = imageName;
                }

                if (!_LocalImageMap.ContainsKey(pid))
                {
                    _LocalImageMap[pid] = new Dictionary<UInt64, string>();
                }

                for (var va = imageBase; va < imageBase + imageSize; va += 64 * 1024)
                {
                    _LocalImageMap[pid][va] = imageName;
                }
            }
        }

        public static void RemoveProcess(uint pid)
        {
            _LocalImageMap.Remove(pid);
            _ProcessNameMap.Remove(pid);
        }

        public static string GetProcessName(uint pid)
        {
            return _ProcessNameMap.ContainsKey(pid) ? _ProcessNameMap[pid] : $"pid:{pid}";
        }

        public static string GetModuleName(uint pid, UInt64 address)
        {
            address &= ~0xFFFFul; // align to default allocation granularity (64K)

            if (IsInSystemImageRange(address) && _SharedDllMap.ContainsKey(address))
                return _SharedDllMap[address];

            if (_LocalImageMap.ContainsKey(pid) && _LocalImageMap[pid].ContainsKey(address))
                return _LocalImageMap[pid][address];

            // This could be a module loaded before we started, or a call from private memory such as JIT or shellcode.
            return IsInSystemImageRange(address) ? "[Image]" : "[Private]";
        }

        public static string GetClosestSymbol(uint pid, UInt64 address)
        {
            var symbolInfo = new SYMBOL_INFO
            {
                SizeOfStruct = SIZE_OF_SYMBOL_INFO,
                MaxNameLen = MAX_SYMBOL_LENGTH
            };

            if (!SymFromAddr(CurrentProcess, address, out _, ref symbolInfo))
            {
                return GetModuleName(pid, address);
            }

            if (symbolInfo.NameLen > MAX_SYMBOL_LENGTH)
                throw new ApplicationException($"SymFromAddr() buffer too small");

            return $"{GetModuleName(pid, address)}!{symbolInfo.Name.Split('<')[0]}"; // strip decorations
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions
        [DllImport("Dbghelp.dll")]
        public static extern int SymSetOptions(
            int SymOptions);

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize
        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymInitialize(
            SafeProcessHandle hProcess,
            StringBuilder UserSearchPath,
            bool fInvadeProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-symbol_info
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct SYMBOL_INFO
        {
            public UInt32 SizeOfStruct;
            public UInt32 TypeIndex;
            public UInt64 Reserved;
            public UInt64 Reserved2;
            public UInt32 Index;
            public UInt32 Size;
            public UInt64 ModBase;
            public UInt32 Flags;
            public UInt64 Value;
            public UInt64 Address;
            public UInt32 Register;
            public UInt32 Scope;
            public UInt32 Tag;
            public UInt32 NameLen;
            public UInt32 MaxNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] // hardcoded for convenience - not robust
            public string Name;
        }
        private static readonly UInt32 MAX_SYMBOL_LENGTH = 128;
        private static readonly UInt32 SIZE_OF_SYMBOL_INFO = (uint)(Marshal.SizeOf(new SYMBOL_INFO()) - MAX_SYMBOL_LENGTH);

        // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfromaddr
        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymFromAddr(
            SafeProcessHandle hProcess,
            UInt64 Address,
            out UInt64 Displacement,
            ref SYMBOL_INFO Symbol);
    }
}
