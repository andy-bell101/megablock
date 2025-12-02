#!/usr/bin/env python3
import re
import urllib.request


space_regex = re.compile(r"\s+")
def identity(x):
    return x
def space_split(x):
    return space_regex.split(x)[1]
def leading_bars(x):
    return x.split("|")[2][:-1]


url_mappers = {
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts": space_split,
    "https://v.firebog.net/hosts/AdguardDNS.txt": identity,
    "https://v.firebog.net/hosts/Admiral.txt": identity,
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt": space_split,
    "https://v.firebog.net/hosts/Easylist.txt": identity,
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext": space_split,
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts": space_split,
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts": space_split,
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt": None,
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt": None,
    "https://v.firebog.net/hosts/Prigent-Crypto.txt": lambda x: x[7:],
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts": space_split,
    "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt": identity,
    "https://phishing.army/download/phishing_army_blocklist_extended.txt": identity,
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt": lambda x: space_regex.split(x)[0],
    "https://v.firebog.net/hosts/RPiList-Malware.txt": leading_bars,
    "https://v.firebog.net/hosts/RPiList-Phishing.txt": leading_bars,
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt": identity,
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts": identity,
    "https://urlhaus.abuse.ch/downloads/hostfile/": lambda x: x.split('\t')[1],
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt": space_split,
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts": space_split,
    "https://v.firebog.net/hosts/static/w3kbl.txt": identity,
    "https://v.firebog.net/hosts/Easyprivacy.txt": identity,
    "https://v.firebog.net/hosts/Prigent-Ads.txt": identity,
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts": space_split,
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt": space_split,
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt": space_split,
}
all_hosts = set()
for url, func in url_mappers.items():
    if func is None:
        continue
    with urllib.request.urlopen(url, timeout=5) as response:
        text = response.read().decode("utf-8")
    filtered_lines = {
        x for line in text.splitlines()
        if line and not line.startswith("#") and (x:=func(line))
    }
    if any(" " in line for line in filtered_lines):
        print(url)
        # print(filtered_lines)
    all_hosts |= filtered_lines

with open("hosts.txt", "w") as f:
    f.writelines(x + "\n" for x in sorted(all_hosts))

