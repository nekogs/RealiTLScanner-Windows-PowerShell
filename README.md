<p dir="auto"><a href="/README.md">English</a> | <a href="/README.fa.md">فارسی</a> | <a href="/README.ar_EG.md">العربية</a> | <a href="/README.zh.md">中文</a> | <a href="/README.es.md">Español</a> | <a href="/README.ru.md">Русский</a> | <a href="/README.tr_TR.md">Türkçe</a></p>

# RealiTLScanner — Windows PowerShell

A port of [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) to PowerShell. It looks for TLS servers that suit Xray REALITY as `dest`: TLS 1.3, ALPN `h2`, and a certificate with a CN and an issuer organization. The script also checks DNS and highlights other people's proxy sites.

## Download

Download [the ZIP archive](https://github.com/nekogs/RealiTLScanner-Windows-PowerShell/releases/latest/download/RealiTLScanner-Windows-PowerShell-main.zip) and unpack it into any folder. It holds `RealiTLScanner.ps1` and `RealiTLScanner.cmd`. Nothing else is needed: Windows PowerShell 5.1 from Windows 10/11 or PowerShell 7 is enough.

## Run

Windows does not run downloaded `.ps1` files by default, so start the script like this:

```powershell
powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
```

### Run with a double click

Double-click `RealiTLScanner.cmd`. It starts the script and asks for an IP, CIDR or domain to scan. An IP or a domain is scanned until you press Ctrl+C. The results are saved to `out.csv` next to the script, and the window stays open until you press Enter. If Windows shows "Windows protected your PC", click "More info" and then "Run anyway".

## Usage

It is recommended to run the scanner locally: running it on a VPS may get the server flagged.

The commands below are run in a PowerShell window opened in the script folder. Run this once in that window first:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

```powershell
# Show help
.\RealiTLScanner.ps1

# Scan a specific IP, IP CIDR or domain:
.\RealiTLScanner.ps1 -addr 1.2.3.4
# Note: infinite mode turns on automatically when `addr` is an IP or a domain (ip, ip-1, ip+1, ... until Ctrl+C)

# Scan a list of targets from a file (one per line):
.\RealiTLScanner.ps1 -in in.txt

# Crawl domains from a URL and scan them:
.\RealiTLScanner.ps1 -url https://launchpad.net/ubuntu/+archivemirrors

# Specify a port to scan, default: 443
.\RealiTLScanner.ps1 -addr 1.1.1.1 -port 443

# Show verbose output, including failed scans and unsuitable targets:
.\RealiTLScanner.ps1 -addr 1.2.3.0/24 -v

# Save results to a file, default: out.csv
.\RealiTLScanner.ps1 -addr www.microsoft.com -out file.csv

# Set a thread count, default: 2
.\RealiTLScanner.ps1 -addr wiki.ubuntu.com -thread 10

# Set a timeout for each scan, default: 10 (seconds)
.\RealiTLScanner.ps1 -addr 107.172.1.1/16 -timeout 5

# Scan IPv6 addresses as well as IPv4:
.\RealiTLScanner.ps1 -in in.txt -46

# Turn off the DNS check of the certificate domain (on by default):
.\RealiTLScanner.ps1 -addr 1.2.3.4 -check-dns=false

# Print logs in the format of the original RealiTLScanner:
.\RealiTLScanner.ps1 -addr 1.2.3.4 -raw
```

### Enable GeoIP

To show the country of each IP, put a MaxMind GeoLite2/GeoIP2 Country database named `Country.mmdb` into the folder you run the script from. You can download one [here](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb).

## Support the author

The script's author is a political prisoner in Russia. If you can spare something for
instant noodles, I'd be grateful!

|           | Address                                                                 |
|-----------|-----------------------------------------------------------------------|
| 💵 USDT (ERC-20) | `0x23c23dc5ed6888d9287da95cba454d4889241202` |
| ₿ BTC      | `bc1q7x2ez0atrtgq0qc5n3phszud0d3geuqvzhhhtu` |
