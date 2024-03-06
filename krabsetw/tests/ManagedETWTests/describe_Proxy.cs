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
    public class describe_Proxy
    {
        [TestMethod]
        public void it_should_raise_OnEvent_for_user_trace()
        {
            var called = false;

            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new Provider(PowerShellEvent.ProviderId);
            provider.OnEvent += e => { called = true; };

            trace.Enable(provider);
            proxy.PushEvent(PowerShellEvent.CreateRecord("user data", "context info", "payload"));

            Assert.IsTrue(called, "proxy call raised on event");
        }

        [TestMethod]
        public void it_should_raise_OnEvent_for_raw_provider_on_user_trace()
        {
            var called = false;

            var trace = new UserTrace();
            var proxy = new Proxy(trace);

            var provider = new RawProvider(PowerShellEvent.ProviderId);
            provider.OnEvent += e => { called = true; };

            trace.Enable(provider);
            proxy.PushEvent(PowerShellEvent.CreateRecord("user data", "context info", "payload"));

            Assert.IsTrue(called, "proxy call raised on event");
        }

        [TestMethod]
        public void it_should_raise_OnEvent_for_kernel_trace()
        {
            var called = false;

            var trace = new KernelTrace();
            var proxy = new Proxy(trace);

            var provider = new ImageLoadProvider();
            provider.OnEvent += e => { called = true; };

            trace.Enable(provider);
            proxy.PushEvent(ImageLoadEvent.CreateRecord(123, "file.exe"));

            Assert.IsTrue(called, "proxy call raised on event");
        }

        [TestMethod]
        public void it_should_raise_OnEvent_for_matching_event_filter()
        {
            var called = false;

            var filter = new EventFilter(Filter.AnyEvent());
            var proxy = new Proxy(filter);

            filter.OnEvent += e => { called = true; };

            proxy.PushEvent(PowerShellEvent.CreateRecord("user data", "context info", "payload"));

            Assert.IsTrue(called, "proxy call raised on event");
        }

        [TestMethod]
        public void it_should_not_raise_OnEvent_for_not_matching_event_filter()
        {
            var called = false;

            var filter = new EventFilter(Filter.Not(Filter.AnyEvent()));
            var proxy = new Proxy(filter);

            filter.OnEvent += e => { called = true; };

            proxy.PushEvent(PowerShellEvent.CreateRecord("user data", "context info", "payload"));

            Assert.IsFalse(called, "proxy call raised on event");
        }
    }
}
