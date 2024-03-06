// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Kernel;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS
{
    using Events;

    public class describe_EventRecord
    {
        [TestClass]
        public class UserEvents : describe_EventRecord
        {
            UserTrace trace;
            Proxy proxy;

            [TestInitialize]
            public void before_each()
            {
                trace = new UserTrace();
                proxy = new Proxy(trace);
            }

            [TestMethod]
            public void it_should_read_provider_id()
            {
                var provider = new Provider(PowerShellEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    Assert.AreEqual(PowerShellEvent.ProviderId, e.ProviderId);
                };

                trace.Enable(provider);
                proxy.PushEvent(PowerShellEvent.CreateRecord(
                    String.Empty, String.Empty, String.Empty));
            }

            [TestMethod]
            public void it_should_read_event_id()
            {
                var provider = new Provider(PowerShellEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    Assert.AreEqual(PowerShellEvent.EventId, e.Id);
                };

                trace.Enable(provider);
                proxy.PushEvent(PowerShellEvent.CreateRecord(
                    String.Empty, String.Empty, String.Empty));
            }

            [TestMethod]
            public void it_should_parse_unicode_strings()
            {
                var data = "This is some user data";
                var prop = PowerShellEvent.UserData;

                var provider = new Provider(PowerShellEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    Assert.AreEqual(data, e.GetUnicodeString(prop));
                    Assert.AreEqual(data, e.GetUnicodeString(prop, String.Empty));

                    string result;
                    Assert.IsTrue(e.TryGetUnicodeString(prop, out result));
                    Assert.AreEqual(data, result);
                };

                trace.Enable(provider);
                proxy.PushEvent(PowerShellEvent.CreateRecord(
                    data, String.Empty, String.Empty));
            }

            [TestMethod]
            public void it_should_parse_ansi_strings()
            {
                var data = "http://www.microsoft.com";
                var prop = WinINetEvent.URL;

                var provider = new Provider(WinINetEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    Assert.AreEqual(data, e.GetAnsiString(prop));
                    Assert.AreEqual(data, e.GetAnsiString(prop, String.Empty));

                    string result;
                    Assert.IsTrue(e.TryGetAnsiString(prop, out result));
                    Assert.AreEqual(data, result);
                };

                trace.Enable(provider);
                proxy.PushEvent(WinINetEvent.CreateRecord(
                    data, String.Empty, 200));
            }

            //[TestMethod]
            //public void it_should_parse_counted_strings()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_ip_addresses()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_int8()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_uint8()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_int16()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_uint16()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_int32()
            //{
            //}

            [TestMethod]
            public void it_should_parse_uint32()
            {
                var data = 200u;
                var prop = WinINetEvent.Status;

                var provider = new Provider(WinINetEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    Assert.AreEqual(data, e.GetUInt32(prop));
                    Assert.AreEqual(data, e.GetUInt32(prop, 0u));

                    uint result;
                    Assert.IsTrue(e.TryGetUInt32(prop, out result));
                    Assert.AreEqual(data, result);
                };

                trace.Enable(provider);
                proxy.PushEvent(WinINetEvent.CreateRecord(
                    String.Empty, String.Empty, data));
            }

            //[TestMethod]
            //public void it_should_parse_int64()
            //{
            //}

            //[TestMethod]
            //public void it_should_parse_uint64()
            //{
            //}

            [TestMethod]
            public void it_should_marshal_user_data()
            {
                var data = "This is some user data";

                var provider = new Provider(PowerShellEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    var bytes = e.CopyUserData();
                    var str = Encoding.Unicode.GetString(bytes);

                    Assert.IsTrue(str.Contains(data));
                    Assert.AreEqual(e.UserDataLength, bytes.Length);
                };

                trace.Enable(provider);
                proxy.PushEvent(PowerShellEvent.CreateRecord(
                    data, String.Empty, String.Empty));
            }

            [TestMethod]
            public void it_should_parse_binary()
            {
                var data = 0x01020304u;
                var prop = WinINetEvent.Status;

                var provider = new Provider(WinINetEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    byte[] binaryData = e.GetBinary(prop);

                    Assert.AreEqual(sizeof(int), binaryData.Length);
                    Assert.AreEqual(data, BitConverter.ToUInt32(binaryData, 0));

                    Assert.IsTrue(e.TryGetBinary(prop, out binaryData));
                    Assert.AreEqual(data, BitConverter.ToUInt32(binaryData, 0));
                };

                trace.Enable(provider);
                proxy.PushEvent(WinINetEvent.CreateRecord(
                    String.Empty, String.Empty, data));
            }

            [TestMethod]
            public void it_should_read_container_id()
            {
                Guid guid = new Guid();
                var provider = new Provider(PowerShellEvent.ProviderId);
                provider.OnEvent += e =>
                {
                    Guid containerId;
                    Assert.IsTrue(e.TryGetContainerId(out containerId));
                    Assert.AreEqual(containerId, guid);
                };

                trace.Enable(provider);
                proxy.PushEvent(PowerShellEvent.CreateRecordWithContainerId(
                    "Test data", String.Empty, String.Empty, guid));
            }
        }

        [TestClass]
        public class KernelEvents : describe_EventRecord
        {
            KernelTrace trace;
            Proxy proxy;

            [TestInitialize]
            public void before_each()
            {
                trace = new KernelTrace();
                proxy = new Proxy(trace);
            }

            // TODO: this really doesn't need to be exhaustive again for all
            // types, maybe this should be moved into a kernel trace test?

            [TestMethod]
            public void it_should_parse_unicode_strings()
            {
                var data = "file.exe";
                var prop = ImageLoadEvent.FileName;

                var provider = new ImageLoadProvider();
                provider.OnEvent += e =>
                {
                    Assert.AreEqual(data, e.GetUnicodeString(prop));
                    Assert.AreEqual(data, e.GetUnicodeString(prop, String.Empty));

                    string result;
                    Assert.IsTrue(e.TryGetUnicodeString(prop, out result));
                    Assert.AreEqual(data, result);
                };

                trace.Enable(provider);
                proxy.PushEvent(PowerShellEvent.CreateRecord(
                    data, String.Empty, String.Empty));
            }
        }
    }
}
