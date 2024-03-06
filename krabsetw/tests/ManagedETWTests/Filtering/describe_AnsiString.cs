// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;

namespace EtwTestsCS.Filtering
{
    using Events;

    [TestClass]
    public class describe_AnsiString
    {
        // Is
        [TestMethod]
        public void when_values_are_same_is_should_match()
        {
            var data = "Test";
            var query = data;
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Is(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_values_are_not_same_is_should_not_match()
        {
            var data = "Test";
            var query = "Foobar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Is(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        [TestMethod]
        public void when_values_differ_only_in_case_is_should_not_match()
        {
            var data = "Test";
            var query = "TEST";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Is(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // IEquals
        [TestMethod]
        public void when_values_differ_in_case_iequals_should_match()
        {
            var data = "Test";
            var query = "TEST";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IEquals(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_values_differ_other_than_case_iequals_should_not_match()
        {
            var data = "Test";
            var query = "Foobar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Is(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // Contains
        [TestMethod]
        public void when_data_contains_query_contains_should_match()
        {
            var data = "Foo Bar Baz";
            var query = "Bar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Contains(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_does_not_contain_query_contains_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "Buzz";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Contains(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_contains_query_but_differs_in_case_contains_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "BAR";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.Contains(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // IContains
        [TestMethod]
        public void when_data_contains_query_icontains_should_match()
        {
            var data = "Foo Bar Baz";
            var query = "Bar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IContains(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_contains_query_but_differs_in_case_icontains_should_match()
        {
            var data = "Foo Bar Baz";
            var query = "BAR";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IContains(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_does_not_contain_query_icontains_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "Buzz";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IContains(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // Starts With
        [TestMethod]
        public void when_data_starts_with_query_startswith_should_match()
        {
            var data = "Foo Bar Baz";
            var query = "Foo";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.StartsWith(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_contains_but_does_not_start_with_query_startswith_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "Bar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.StartsWith(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_does_not_start_with_query_startswith_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "Bar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.StartsWith(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_starts_with_query_but_differs_in_case_startswith_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "FOO";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.StartsWith(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        // IStarts With
        [TestMethod]
        public void when_data_starts_with_query_istartswith_should_match()
        {
            var data = "Foo Bar Baz";
            var query = "Foo";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IStartsWith(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_starts_with_query_but_differs_in_case_istartswith_should_match()
        {
            var data = "Foo Bar Baz";
            var query = "FOO";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IStartsWith(WinINetEvent.Verb, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_contains_but_does_not_start_with_query_istartswith_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "Bar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IStartsWith(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }

        [TestMethod]
        public void when_data_does_not_start_with_query_istartswith_should_not_match()
        {
            var data = "Foo Bar Baz";
            var query = "Bar";
            var record = WinINetEvent.CreateRecord(String.Empty, data, 0u);
            var predicate = AnsiString.IStartsWith(WinINetEvent.Verb, query);

            Assert.IsFalse(predicate.Test(record));
        }
    }
}
