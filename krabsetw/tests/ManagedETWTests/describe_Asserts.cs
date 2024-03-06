// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS
{
    using Events;

    // This class is really testing the ability to disable certain
    // type checking in krabs with preprocessor definitions. I'm not
    // really a fan of having different test behavior in debug/release
    // but it's actually the difference that needs to be tested.

    // NOTE: if you touch this class, make sure it builds/runs in
    // both release and debug configurations.

    [TestClass]
    public class describe_Asserts
    {
        UserTrace trace;
        Proxy proxy;

        [TestInitialize]
        public void before_each()
        {
            trace = new UserTrace();
            proxy = new Proxy(trace);
        }

#if DEBUG
        [TestMethod]
        [ExpectedException(typeof(TypeMismatchAssert))]
        public void when_requesting_mismatched_type_in_debug_it_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(data, e.GetInt32(prop));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        public void when_requesting_correct_type_in_debug_it_should_not_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(data, e.GetUInt32(prop));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        [ExpectedException(typeof(TypeMismatchAssert))]
        public void when_requesting_wrong_size_in_debug_it_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(data, e.GetInt16(prop));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }
#else

        [TestMethod]
        public void when_requesting_mismatched_type_in_release_it_should_not_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(data, (uint)e.GetInt32(prop));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        public void when_requesting_correct_type_in_release_it_should_not_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(data, e.GetUInt32(prop));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        [ExpectedException(typeof(ParserException))]
        public void when_requesting_wrong_size_in_release_it_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(data, e.GetInt16(prop));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }
#endif

    }
}
