# sbnMerlin - automatic subnet creation for AsusWRT-Merlin Guest Networks
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/96872a441a714fc6b88d6e58609461d1)](https://app.codacy.com/gh/janico82/sbnMerlin/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![Shellcheck](https://github.com/janico82/sbnMerlin/actions/workflows/shellcheck.yml/badge.svg)

## v1.0.1
### Updated on 2024-02-06
## About
Feature expansion of Guest networks on AsusWRT-Merlin, including, but not limited to:

*   Automatic creation of ethernet bridge instances, based on active guest wireless.
*   Allow manage wifi interface isolation included in the bridge instance.
*   Include other ethernet ports in the bridge instance.
*   Allow Internet and one-way access for the bridge instance.
*   Allow custom DHCP settings for the bridge instance.
*   Allow ethernet bridge and packet filtering rules for the bridge instance.

Running configuration example:
```sh
root:/jffs/scripts# brctl show
bridge name     bridge id               STP enabled     interfaces
br0             8000.04421xxxxxxx       yes             eth1
                                                        eth3
                                                        eth5
                                                        eth6
                                                        eth7
br8             8000.04421xxxxxxy       yes             eth2
                                                        eth4
                                                        wl0.2
                                                        wl1.2

root:/jffs/scripts# ifconfig br8
br8       Link encap:Ethernet  HWaddr ab:cb:ef:01:23:45
          inet addr:192.168.108.1  Bcast:192.168.108.255  Mask:255.255.255.0
          UP BROADCAST RUNNING ALLMULTI MULTICAST  MTU:1500  Metric:1
          RX packets:16764544 errors:0 dropped:25196 overruns:0 frame:0
          TX packets:84869956 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:5262801805 (4.9 GiB)  TX bytes:116707141040 (108.6 GiB)
```

sbnMerlin is free to use under the [GNU General Public License version 3](https://opensource.org/licenses/GPL-3.0) (GPL 3.0).

### Supporting development
Love the script and want to support future development? Any and all donations gratefully received!

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/donate/?business=7GJ9GM39PF3NS&no_recurring=0&item_name=for+support+of+continued+development+of+Asuswrt-Merlin+addons&currency_code=EUR)

## Supported firmware versions
### Core sbnMerlin features
You must be running firmware no older than:
*   [Asuswrt-Merlin](https://www.asuswrt-merlin.net/) 384.5
*   [john9527 fork](https://www.snbforums.com/threads/fork-asuswrt-merlin-374-43-lts-releases-v37ea.18914/) 374.43_32D6j9527

## Installation
Using your preferred SSH client/terminal, copy and paste the following command, then press Enter:

```sh
/usr/sbin/curl -fsL --retry 3 "https://janico82.gateway.scarf.sh/asuswrt-merlin/sbnMerlin/master/sbnMerlin.sh" -o /jffs/scripts/sbnMerlin && chmod 0755 /jffs/scripts/sbnMerlin && /jffs/scripts/sbnMerlin install
```

Please then follow instructions shown on-screen.

## Usage
### Command Line
To launch the sbnMerlin menu after installation, use:
```sh
sh /jffs/scripts/sbnMerlin
```
```sh
#############################################################
##            _           __  __           _ _             ##
##        ___| |__  _ __ |  \/  | ___ _ __| (_)_ __        ##
##       / __| '_ \| '_ \| |\/| |/ _ \ '__| | | '_ \       ##
##       \__ \ |_) | | | | |  | |  __/ |  | | | | | |      ##
##       |___/_.__/|_| |_|_|  |_|\___|_|  |_|_|_| |_|      ##
##                                                         ##
##          https://github.com/janico82/sbnMerlin          ##
##                                                         ##
#############################################################
   sbnMerlin Main menu - version: 1.0.0
   1.   Edit configuration
   2.   Run configuration
   d.   Run diagnostics
   u.   Update check
   e.   Exit
   z.   Uninstall
#############################################################
Choose an option: 
```

## FAQs
### Details of sbnMerlin configuration items:
sbnMerlin automatically creates ethernet bridge instances {bridge} for network isolation, and for each bridge it's possible to define a set of configurations, detailed below. The allowed ethernet bridge instances are: br3, br4, br5, br6, br8 and br9.

sbnMerlin automatism is based on the following rules, sbMerlin creates:
*   ethernet bridge(br3) instance if the wireless interface(wl0.2) is enabled and with lan access disabled.
*   ethernet bridge(br4) instance if the wireless interface(wl1.2) is enabled and with lan access disabled.
*   ethernet bridge(br5) instance if the wireless interface(wl0.3) is enabled and with lan access disabled.
*   ethernet bridge(br6) instance if the wireless interface(wl1.3) is enabled and with lan access disabled.
*   ethernet bridge(br8) instance if both wireless interfaces(wl0.2, wl1.2) are enabled and with lan access disabled.
*   ethernet bridge(br9) instance if both wireless interfaces(wl0.3, wl1.3) are enabled and with lan access disabled.

#### {bridge}_enabled
Bridge configuration enabled. (0=False/1=True/Default=0). Example: br8_enabled=1

#### {bridge}_ifnames
List of interface(s) names that will be port(s) of the bridge. Example: br8_ifnames="wl0.2 wl1.2 eth2 eth4"

#### {bridge}_ipaddr
IP address setting of the bridge. Example: br8_ipaddr="192.168.108.1"

#### {bridge}_netmask
IP address netmask setting of the bridge. Example: br8_netmask="255.255.255.0"

#### {bridge}_dhcp_start
Start IP address of the bridge DHCP pool. Example: br8_dhcp_start="192.168.108.2"

#### {bridge}_dhcp_end
End IP address of the bridge DHCP pool. Example: br8_dhcp_end="192.168.108.254"

#### {bridge}_staticlist
IP address reservation of the bridge. Example: br8_staticlist=\<ab:cd:ef:01:23:45\>192.168.108.10\>8.8.8.8\>HOMEPC\<ab:cd:ef:01:23:46\>192.168.108.11\>\>Xbox\<ab:cd:ef:01:23:47\>192.168.168.108.12\>\>

Syntax: \<MAC Address\>IP Address\>DNS Server (Optional)\>Host Name (Optional)

#### {bridge}_ap_isolate
When this feature is enabled, wireless clients or devices will not be able to communicate with each other. (0=False/1=True/Default=1) Example: br8_ap_isolate=1

#### {bridge}_allow_internet
Allow Internet access for the bridge devices. (0=False/1=True/Default=0) Example: br8_allow_internet=1

#### {bridge}_allow_onewayaccess
Allow one-way access for the bridge devices. (0=False/1=True/Default=0) Example: br8_allow_onewayaccess=1

### Custom ethernet bridge and packet filtering rules
sbnMerlin supports custom scripts after setting up the device firewall for each bridge. To use this feature, create the custom script file in the appropriate directory with the following syntax: {bridge}_{iptables or ebtables}.sh extension. e.g.
```sh
/jffs/addons/sbnMerlin.d/uscripts/br8_iptables.sh
```
Remember to make it executable with
```sh
chmod +x /jffs/addons/sbnMerlin.d/uscripts/br8_iptables.sh
```
An example script to allow bridge access to router services: ntp
```sh
#!/bin/sh
iptables -I INPUT -i br8 -p udp -m multiport --dports 123 -m comment --comment "(sbnMerlin)" -j ACCEPT
```

## Scarf Gateway
Installs and updates for this addon are redirected via the [Scarf Gateway](https://about.scarf.sh/scarf-gateway) by [Scarf](https://about.scarf.sh/about). This allows gather data on the number of new installations of this addon or how often users check for updates. Scarf Gateway functions similarly to a link shortener like bit.ly, redirecting traffic as a domain gateway.

Please refer to Scarf's [Privacy Policy](https://about.scarf.sh/privacy) for more information about the data that is collected and how it is processed.
