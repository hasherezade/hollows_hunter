# hollows_hunter
![](./logo/logo2_128.png)

[![Build status](https://ci.appveyor.com/api/projects/status/nsc2eux5986y1shq?svg=true)](https://ci.appveyor.com/project/hasherezade/hollows-hunter)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/0c149fcd62084f96ac0c131e4473dbdf)](https://app.codacy.com/gh/hasherezade/hollows_hunter/dashboard?branch=master)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hasherezade/hollows_hunter)](https://github.com/hasherezade/hollows_hunter/commits)
[![Last Commit](https://img.shields.io/github/last-commit/hasherezade/hollows_hunter/master)](https://github.com/hasherezade/hollows_hunter/commits)

[![GitHub release](https://img.shields.io/github/release/hasherezade/hollows_hunter.svg)](https://github.com/hasherezade/hollows_hunter/releases)
[![GitHub release date](https://img.shields.io/github/release-date/hasherezade/hollows_hunter?color=blue)](https://github.com/hasherezade/hollows_hunter/releases)
[![Github All Releases](https://img.shields.io/github/downloads/hasherezade/hollows_hunter/total.svg)](https://github.com/hasherezade/hollows_hunter/releases)
[![Github Latest Release](https://img.shields.io/github/downloads/hasherezade/hollows_hunter/latest/total.svg)](https://github.com/hasherezade/hollows_hunter/releases)

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://github.com/hasherezade/hollows_hunter/blob/master/LICENSE)
[![Platform Badge](https://img.shields.io/badge/Windows-0078D6?logo=windows)](https://github.com/hasherezade/hollows_hunter)

Hollows Hunter is a command-line application based on [PE-sieve](https://github.com/hasherezade/pe-sieve.git) passive memory scanner. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches). While in case of PE-sieve you can select the process only by its PID, Hollows Hunter allows to select them by various criteria, such as:
+ list of PIDs
+ list of names
+ the time of creation (relatively to the Hollows Hunter execution time)

If no specific target is selected, it proceeds to scan all available processes.

Hollows Hunter allows also for continuous memory scanning, via `/loop` argument, or by being run as an ETW listener: in `/etw` mode (64-bit version only).

> [!IMPORTANT]  
> The available arguments are documented on [Wiki](https://github.com/hasherezade/pe-sieve/wiki). They can also be listed using the argument `/help`.

📦 Uses: [PE-sieve](https://github.com/hasherezade/pe-sieve.git) (the [library version](https://github.com/hasherezade/pe-sieve/wiki/2.-How-to-build)).

❓ [PE-sieve FAQ - Frequently Asked Questions](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ)

📖 [Read Wiki](https://github.com/hasherezade/hollows_hunter/wiki)


## Clone

Use recursive clone to get the repo together with all the submodules:

```console
git clone --recursive https://github.com/hasherezade/hollows_hunter.git
```

## Builds

Download the latest [release](https://github.com/hasherezade/hollows_hunter/releases), or [read more](https://github.com/hasherezade/hollows_hunter/wiki#download).

![](https://community.chocolatey.org/favicon.ico) Available also via [Chocolatey](https://community.chocolatey.org/packages/hollowshunter)
