// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Kernel;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS
{
    using Events;

    [TestClass]
    public class describe_OnError
    {
        [TestMethod]
        public void schema_not_found_should_raise_onerror_on_user_trace()
        {
            var onEventCalled = false;
            var onErrorCalled = false;

            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(PowerShellEvent.ProviderId);
            provider.OnEvent += e => { onEventCalled = true; };
            provider.OnError += e => { onErrorCalled = true; };

            var record = PowerShellEvent.CreateRecord("user data", "context info", "payload");

            // munge the event so the schema can't be found
            record.Id = (ushort)1234;

            trace.Enable(provider);
            proxy.PushEvent(record);

            Assert.IsFalse(onEventCalled, "schema not found raised OnEvent");
            Assert.IsTrue(onErrorCalled, "schema not found raised OnError");
        }

        //[TestMethod]
        //public void schema_not_found_should_raise_onerror_on_kernel_trace()
        //{
        //    var onEventCalled = false;
        //    var onErrorCalled = false;

        //    var trace = new KernelTrace();
        //    var proxy = new Proxy(trace);

        //    var provider = new ImageLoadProvider();
        //    provider.OnEvent += e => { onEventCalled = true; };
        //    provider.OnError += e => { onErrorCalled = true; };

        //    var record = ImageLoadEvent.CreateRecord(123u, "file.exe");

        //    // munge the event so the schema can't be found
        //    // TODO: turns out the kernel event schemas don't
        //    // care about version, id, or opcode so I can't
        //    // trick it.

        //    trace.Enable(provider);
        //    proxy.PushEvent(record);

        //    Assert.IsFalse(onEventCalled, "schema not found raised OnEvent");
        //    Assert.IsTrue(onErrorCalled, "schema not found raised OnError");
        //}

        [TestMethod]
        public void schema_not_found_should_raise_onerror_on_event_filter()
        {
            var onEventCalled = false;
            var onErrorCalled = false;

            var filter = new EventFilter(Filter.AnyEvent());
            var proxy = new Proxy(filter);

            filter.OnEvent += e => { onEventCalled = true; };
            filter.OnError += e => { onErrorCalled = true; };

            var record = PowerShellEvent.CreateRecord("user data", "context info", "payload");

            // munge the event so the schema can't be found
            record.Id = (ushort)1234;

            proxy.PushEvent(record);

            Assert.IsFalse(onEventCalled, "schema not found raised OnEvent");
            Assert.IsTrue(onErrorCalled, "schema not found raised OnError");
        }
    }
}
