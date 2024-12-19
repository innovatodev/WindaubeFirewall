# WindaubeFirewall

Early development personal project.

## Description

WindaubeFirewall is a robust (Windows 11 24H2+) firewall and optional DNS server that uses a kernel driver signed and provided by [Safing](https://github.com/safing/portmaster) to intercept network packets and DNS requests.

It's designed to be a simple yet powerful tool, currently usable only via the tray context menu and by modifying yaml settings files.

Using .net 9.0 and Windows 10.0.26100.0 SDK.

## **Windaube** meaning

The term "windaube" is a play on words used in French to mock or criticize Microsoft Windows. It combines:

- **Windows**, the operating system by Microsoft.
- **Daube**, a French slang term meaning "junk" or "something of poor quality."
- Together, **Windaube** humorously translates to something like "Window-junk" or "Windows-trash." It’s often used by tech enthusiasts, Linux users, or others who might be frustrated with Windows due to perceived flaws, bugs, or limitations.

It's informal and used in a **joking** or **sarcastic** tone rather than as a serious critique.

## Acknowledgments

Thanks to [Safing](https://github.com/safing/portmaster) for the kernel driver and inspiration.

Many features are based on or similar to Portmaster, with personal modifications.

This project is not intended for daily use and may never be.

For a reliable solution, consider using Portmaster on Windows it's a great tool that works well.

## Features

- Intercepts network requests at the kernel level and assigns a verdict (Allow/Block/Prompt).
- Intercepts DNS requests and resolves them using custom DNS servers with support for plaintext, DoH, and DoT. If disabled, the system DNS is used and nothing will be redirected forcibly.
- Assigns processes to profiles using custom rules and operators within a robust profile system.
- Supports blocklists:
  - **Offline**: Local files.
  - **Online**: URLs with auto-updates.
- Supports blocklists from DNS requests using preferred upstream servers (Pihole, Adguard, Cloudflare, ...).
- Offers a robust rule system to allow, block, or prompt based on ports, CIDR ranges, protocols, countries, and more. If using WindaubeFirewall as a DNS server, it can also block based on domain names.
- Includes an optional Anti-DNS Bypass feature that blocks DNS queries that cannot be redirected due to encryption.
- Tracks network bandwidth to monitor data sent and received by each process.
- Applies settings first on a per-profile basis, then globally.
- Provides an "Easy" mode that ignores rules and controls access with Allow/Block/Prompt and Forceblock methods (Internet, LAN, Localhost, Incoming).
- Automatically generates profiles based on the process name, path, or type (Windows service, Store app) when first detected on the network.

## Installation

No installer is available yet. Refer to the "How to use" section for development or testing purposes.

## Demo

Default behavior (allowing everything but incoming connections):
![Demo1](https://github.com/innovatodev/WindaubeFirewall/blob/main/Media/demo1.jpg)
![Demo2](https://github.com/innovatodev/WindaubeFirewall/blob/main/Media/demo2.jpg)

Memory usage with ~1M blocklists ips/domains entries:
![Demo3](https://github.com/innovatodev/WindaubeFirewall/blob/main/Media/demo3.jpg)

Bandwidth usage tracking with an active twitch stream:
![Demo4](https://github.com/innovatodev/WindaubeFirewall/blob/main/Media/demo4.jpg)

DNS interception:
![Demo5](https://github.com/innovatodev/WindaubeFirewall/blob/main/Media/demo5.jpg)

DNS not intercepted:
![Demo6](https://github.com/innovatodev/WindaubeFirewall/blob/main/Media/demo6.jpg)

## How to use (for development or test)

1. Clone or download and extract the repository
2. Launch ps1 scripts (or VSCode task):
   - `.\Scripts\DriverUpdate.ps1` (DriverUpdate task) to download latest driver version from Safing.
   - `.\Scripts\BlocklistsUpdate.ps1` (BlocklistsUpdate task) to download latest BuiltIn blocklists (dns bypass).
   - `.\Scripts\IPDataUpdate.ps1` (IPDataUpdate task) to download latest IP Informations databases from Safing.

if everything went well, you should have the following files in the `.\Data` folder:

- `\DriverFiles\portmaster-kext*`
- `\Blocklists\DNS*.txt`
- `\IPData\geoip*.mmdb`

Now you can launch the solution either from VSCode or Visual Studio.

VSCode needs to run as **ADMINISTRATOR** or it will say access denied.

Visual Studio will ask for **ADMINISTRATOR** rights when launching the app if not already.

Double click the tray icon to open some debug windows, they are not intended to stay and they consumes cpu/ram for no others reasons than debbuging.

The driver is deleted when the app exits or when an exception occurs, but in case something went wrong, launch the following script/task:

`.\Scripts\CleanDriver.ps1` (CleanDriver task) it will stops and delete the driver.

**Settings** can be found in the same folder as the application, by default:

 `.\WindaubeFirewall\x64\Debug\net9.0-windows10.0.26100.0\Settings*.yaml`

## Explanation

A new packet is intercepted:

- It is a DNS request.
- It is a Network packet (anything else).

A new plaintext DNS request is intercepted:

1. Our DNS server is enabled: Redirect any DNS request to our DNS server, allow our own requests.
2. Our DNS server is disabled:
   - If profile has DNS Bypass enabled: Allow the request only if its sent to system adapters DNS, block attempts to bypass it.
   - If profile has DNS Bypass disabled: Allow the request without further checks.

A new network packet is intercepted:

1. Matches the packet to a profile using the process name, path, commandline, windows service, store app, etc.
2. If no profile is found, generate a new profile, based on path, service name or store app name.
   - Absorb global settings (blocklists, network actions, etc) to create the profile with global defaults.
3. Process verdict based on profile's rules and settings.

Force blocks are special top-level rules that are applied regardless of any rule, based on network type (Internet, LAN, Localhost, Incoming).

At the end of the verdict processing, if nothing was allowed or blocked, the network default action will apply.

That allows for a very granular control of network traffic.

We can choose simplicify by just managing profiles with forceblocks (Allow an app to just use LAN but no internet by example).

Or we can go full control by managing very specific rules, or changing the default action from allow to block, it should cover any network use case like:

- Blacklist mode: Block everything by default, allow only what is needed.
- Whitelist mode: Allow everything by default, block only what is not needed.
- Prompt mode: Ask the user for every new connection.
- Allow but prompt mode: Allow by default but ask the user for a specific ip, scope or domain, specified by rules.

etc ...

## Dns Server

The DNS server is a simple DNS server that can resolve DNS requests using plaintext (UDP), DoH, or DoT.

Upstream DNS servers can be either selected from first to last, or randomized.

- Blockedif:
  1. `zeroip` the upstream dns returns 0.0.0.0 when a domain is blocked.
  2. `refused` the upstream returns RCODE:5 (refused).
  3. `empty` the upstream returns an empty response (no ip, no cname).
  4. if no Blockif is specified, nothing will be detected as blocked.

By default, the DNS server is disabled. But a list of upstreams servers are provided as examples and debugging purposes.

Can enable the server in the tray icon or yaml.

## Blocklists

Blocklists are used to block domains or ip addresses.

There two types of blocklists:

- **Offline**: Local files placed in `.\Data\Offline\myblocklist.txt`, the name of the file will be used as blocklist name.
- **Online**: URLs with auto-updates, will be updated at a specified interval in hours.

Blocklists can be used for DNS requests (domain) and network packets (ip).

It supports most common blocklists types like:

- Wildcard: Matches patterns like *.123-proxy.net (Type: domain)
- Domain: Matches patterns like 123-proxy.net (Type: domain)
- Hosts: Matches patterns like 0.0.0.0 cdn.0ms.dev  (Type: domain)
- IP: Matches patterns like 1.2.3.4 (can also use blocklists with comments like 1.1.1.1 # dns.cloudflare.com)

Some blocklists are provided as examples and debugging purposes with all sorts of formats.

## Profiles

Profiles are generated by default and separated by processes (one profile = one exact process/service/store app).

A new generated profile will always absorb global settings (blocklists, network actions, etc) to create the profile with global defaults.

But you can create profiles and catch more than just one app.

By example, you can create a profile to store all your portable tools from a folder (recursive):

```yaml
- id: // Grab one from a generated profile and change one number
  name: PortableTools
  fingerprints:
  - type: FullPath
    operator: Prefix
    value: C:\PortableApps\
  isAutoGenerated: false
  isSpecial: false
  icon: // not used yet
  networkAction:
    isSimpleMode: false
    defaultNetworkAction: 1
    forceBlockInternet: false
    forceBlockLAN: false
    forceBlockLocalhost: false
    forceBlockIncoming: true
    blockBypassDNS: true
    incomingRules: []
    outgoingRules: []
  blocklists: []
```

Or one profile for two differents apps with two fingerprints:

```yaml
- id: // Grab one from a generated profile and change one number
  name: CodingProfile
  fingerprints:
  - type: FullPath
    operator: Prefix
    value: C:\Program Files\Git
  - type: FullPath
    operator: Prefix
    value: C:\Program Files (x86)\Microsoft Visual Studio
  isAutoGenerated: false
  isSpecial: false
  icon: // not used yet
  networkAction:
    isSimpleMode: false
    defaultNetworkAction: 1
    forceBlockInternet: false
    forceBlockLAN: false
    forceBlockLocalhost: false
    forceBlockIncoming: true
    blockBypassDNS: true
    incomingRules: []
    outgoingRules: []
  blocklists: []
```

Can also use wildcards (*) to precisely catch an app with dynamic path (like a version number in between):

```yaml
- id: // Grab one from a generated profile and change one number
  name: PortableTools
  fingerprints:
  - type: FullPath
    operator: Wildcard
    value: C:\Users\MYGREATUSERNAME\AppData\Local\Discord\*\Discord.exe
  isAutoGenerated: false
  isSpecial: false
  icon: // not used yet
  networkAction:
    isSimpleMode: false
    defaultNetworkAction: 1
    forceBlockInternet: false
    forceBlockLAN: false
    forceBlockLocalhost: false
    forceBlockIncoming: true
    blockBypassDNS: true
    incomingRules: []
    outgoingRules: []
  blocklists: []
```

Will catch discord updates after updates:

- `C:\Users\MYGREATUSERNAME\AppData\Local\Discord\app-1.0.9174\Discord.exe`
- `C:\Users\MYGREATUSERNAME\AppData\Local\Discord\app-1.0.9175\Discord.exe`
