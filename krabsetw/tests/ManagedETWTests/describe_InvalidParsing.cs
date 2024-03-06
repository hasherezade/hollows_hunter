// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;
using Microsoft.O365.Security.ETW.Testing;

namespace EtwTestsCS
{
    using Events;

    [TestClass]
    public class describe_InvalidParsing
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
        [ExpectedException(typeof(ParserException))]
        public void given_invalid_property_name_parse_should_throw()
        {
            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => e.GetAnsiString("InvalidName");

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, 0u));
        }

#if DEBUG
        [TestMethod]
        [ExpectedException(typeof(TypeMismatchAssert))]
        public void given_invalid_type_try_parse_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;
            short result;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => e.TryGetInt16(prop, out result);

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        [ExpectedException(typeof(TypeMismatchAssert))]
        public void given_invalid_type_parse_with_default_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => e.GetInt16(prop, (short)15);

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        [ExpectedException(typeof(TypeMismatchAssert))]
        public void given_invalid_type_parse_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => e.GetInt16(prop);

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }
#else
        [TestMethod]
        public void given_type_with_mismatched_size_try_parse_should_return_false()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;
            short result;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.IsFalse(e.TryGetInt16(prop, out result));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        public void given_type_with_mismatched_size_parse_default_should_return_default()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;
            short defVal = 15;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => Assert.AreEqual(defVal, e.GetInt16(prop, defVal));

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }

        [TestMethod]
        [ExpectedException(typeof(ParserException))]
        public void given_type_with_mismatched_size_parse_default_should_throw()
        {
            var data = 200u;
            var prop = WinINetEvent.Status;

            var provider = new Provider(WinINetEvent.ProviderId);
            provider.OnEvent +=
                e => e.GetInt16(prop);

            trace.Enable(provider);
            proxy.PushEvent(WinINetEvent.CreateRecord(
                String.Empty, String.Empty, data));
        }
#endif // DEBUG
    }
}
