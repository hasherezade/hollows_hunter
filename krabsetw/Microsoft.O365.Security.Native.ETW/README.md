
Overview
========

ETWLib is a C# library that simplifies interacting with ETW. It allows for any number of traces and providers to be enabled and for client code to register for event notifications from these traces.

ETWLib also provides code to simplify parsing generic event data into strongly typed data types.

Guided Example
==============

ETW has the concept of a trace, where a trace essentially represents a stream of events that can be listened to. It distinguishes between kernel and user traces, where the source of events in a kernel trace comes from the Windows kernel. User trace event sources can be any regular application that is ETW-aware.

ETWLib maintains the differentiation between user and kernel traces (kernel traces are not yet implemented) because their APIs are slightly different.

A `UserTrace` can be named an arbitrary name or a name can be generated for you.

    UserTrace trace = new UserTrace(); // unnamed trace
    UserTrace namedTrace = new UserTrace("Muffins McGoo");

ETWLib represents different sources of ETW events with the concept of a `Provider`. Providers are identified by a GUID, as specified by ETW itself. Providers each have a pair of properties that represent bitflags named `Any` and `All` that are used to do event filtering. If an event meets any of the flags in the `Any` property, registered event callbacks are called. If an event meets all of the bits in the `All` property, registered event callbacks are likewise called.

**NOTE:** The semantics of the `Any` and `All` flag are left to the discretion of the ETW provider. Many providers ignore the `All` flag if the `Any` flag is not set, for example.

    void MyCallbackFunction(EventRecord)
    {}

    Provider powershellProvider = new Provider(Guid.Parse("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));
    powershellProvider.Any = 0x10;
    powershellProvider.OnEvent += MyCallbackFunction;

Providers must be enabled for specific traces in order to have any effect on the event tracing system:

    namedTrace.Enable(powershellProvider);

Once all the providers have been enabled for a trace, the trace must be started. The `UserTrace::start()` method will block while listening for events, so if a program is supposed to do other interesting things while listening for ETW events, the start method needs to called on another thread.

    var t = Task.Run(() => namedTrace.Start());
