// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;

namespace EtwTestsCS.Filtering
{
    using Events;

    [TestClass]
    public class describe_Predicate
    {
        // &&
        [TestMethod]
        public void and_operator_predicate_should_match_if_both_predicates_true()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.op_LogicalAnd(predicate2);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void and_operator_predicate_should_not_match_if_either_predicate_false()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, "Not Found");

            var predicate = predicate1.op_LogicalAnd(predicate2);

            Assert.IsFalse(predicate.Test(record));
        }

        // And
        [TestMethod]
        public void and_predicate_should_match_if_both_predicates_true()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.And(predicate2);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void and_predicate_should_not_match_if_either_predicate_false()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, "Not Found");

            var predicate = predicate1.And(predicate2);

            Assert.IsFalse(predicate.Test(record));
        }

        // ||
        [TestMethod]
        public void or_operator_predicate_should_match_if_both_predicates_true()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.op_LogicalOr(predicate2);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void or_operator_predicate_should_match_if_either_predicate_false()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, "Not Found");

            var predicate = predicate1.op_LogicalOr(predicate2);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void or_operator_predicate_should_not_match_if_both_predicates_false()
        {
            var data = "Test";
            var query = "Not Found";
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.op_LogicalOr(predicate2);

            Assert.IsFalse(predicate.Test(record));
        }

        // Or
        [TestMethod]
        public void or_predicate_should_match_if_both_predicates_true()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.Or(predicate2);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void or_predicate_should_match_if_either_predicate_false()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, "Not Found");

            var predicate = predicate1.Or(predicate2);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void or_predicate_should_not_match_if_both_predicates_false()
        {
            var data = "Test";
            var query = "Not Found";
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);
            var predicate2 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.Or(predicate2);

            Assert.IsFalse(predicate.Test(record));
        }

        // !
        [TestMethod]
        public void not_operator_predicate_should_match_if_predicate_false()
        {
            var data = "Test";
            var query = "Not Found";
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.op_LogicalNot();

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void not_operator_predicate_should_not_match_if_predicate_true()
        {
            var data = "Test";
            var query = data;
            var record = PowerShellEvent.CreateRecord(data, String.Empty, String.Empty);
            var predicate1 = UnicodeString.Is(PowerShellEvent.UserData, query);

            var predicate = predicate1.op_LogicalNot();

            Assert.IsFalse(predicate.Test(record));
        }
    }
}
