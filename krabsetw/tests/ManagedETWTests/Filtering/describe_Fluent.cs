// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Microsoft.O365.Security.ETW;

namespace EtwTestsCS.Filtering
{
    using Events;

    [TestClass]
    public class describe_Fluent
    {
        // IsUInt32
        [TestMethod]
        public void when_int32_values_are_same_is_should_match()
        {
            UInt32 data = 5;
            var query = data;
            var record = LogonEvent.CreateRecord(String.Empty, data);
            var predicate = Filter.IsUInt32(LogonEvent.LogonType, query);

            Assert.IsTrue(predicate.Test(record));
        }

        [TestMethod]
        public void when_int32_values_are_not_same_is_should_not_match()
        {
            UInt32 data = 0;
            UInt32 query = 1;
            var record = LogonEvent.CreateRecord(String.Empty, data);
            var predicate = Filter.IsUInt32(LogonEvent.LogonType, query);

            Assert.IsFalse(predicate.Test(record));
        }
    }
}
