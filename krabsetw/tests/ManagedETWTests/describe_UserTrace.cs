// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;
using System.Runtime.InteropServices;

namespace EtwTestsCS
{
    [StructLayout(LayoutKind.Explicit, Size = 200)]
    public ref struct TraceInfo
    {
        [FieldOffset(0)]
        public uint Wnode_BufferSize;
        [FieldOffset(48)]
        public uint BufferSize;
        [FieldOffset(52)]
        public uint MinimumBuffers;
        [FieldOffset(56)]
        public uint MaximumBuffers;
        [FieldOffset(64)]
        public uint LogFileMode;
        [FieldOffset(68)]
        public uint FlushTimer;
        [FieldOffset(120)]
        public uint LoggerNameOffset;
    };

    [TestClass]
    public class describe_UserTrace
    {
        [DllImport("advapi32.dll", CharSet= CharSet.Unicode, SetLastError=true)]
        static extern uint ControlTraceW(ulong SessionHandle, string SessionName, [In, Out] ref TraceInfo Properties, uint ControlCode);

        [TestMethod]
        public void it_should_set_properties()
        {
            var TEST_TRACE_NAME = "krabs C++/CLI properties test";
            uint EVENT_TRACE_CONTROL_QUERY = 0;
            uint ERROR_SUCCESS = 0;

            var trace = new UserTrace(TEST_TRACE_NAME);
            var properties = new EventTraceProperties
            {
                BufferSize = 1024,
                MinimumBuffers = (uint)Environment.ProcessorCount * 2 + 1,
                MaximumBuffers = (uint)Environment.ProcessorCount * 2 + 2,
                FlushTimer = 2,
                LogFileMode = (uint)LogFileModeFlags.FLAG_EVENT_TRACE_REAL_TIME_MODE
            };
            trace.SetTraceProperties(properties);
            trace.Open();

            var info = new TraceInfo
            {
                Wnode_BufferSize = 200,
                LoggerNameOffset = 120
            };            
            var status = ControlTraceW(0, TEST_TRACE_NAME, ref info, EVENT_TRACE_CONTROL_QUERY);
            Assert.IsTrue(status == ERROR_SUCCESS);

            Assert.IsTrue(properties.BufferSize == info.BufferSize);
            Assert.IsTrue(properties.MinimumBuffers == info.MinimumBuffers);
            Assert.IsTrue(properties.MaximumBuffers == info.MaximumBuffers);
            Assert.IsTrue(properties.FlushTimer == info.FlushTimer);
            Assert.IsTrue((uint)LogFileModeFlags.FLAG_EVENT_TRACE_REAL_TIME_MODE == (info.LogFileMode & (uint)LogFileModeFlags.FLAG_EVENT_TRACE_REAL_TIME_MODE));
            Assert.IsTrue((uint)LogFileModeFlags.FLAG_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING != (info.LogFileMode & (uint)LogFileModeFlags.FLAG_EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING));
        }
    }
}
