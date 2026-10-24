<p dir="auto"><a href="/README.md">English</a> | <a href="/README.fa.md">فارسی</a> | <a href="/README.ar_EG.md">العربية</a> | <a href="/README.zh.md">中文</a> | <a href="/README.es.md">Español</a> | <a href="/README.ru.md">Русский</a> | <a href="/README.tr_TR.md">Türkçe</a></p>

# RealiTLScanner — Windows PowerShell

پورت [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) به PowerShell. سرورهای TLS مناسب برای `dest` در Xray REALITY را پیدا می‌کند: TLS 1.3، ALPN `h2` و گواهی‌ای که CN و سازمان صادرکننده دارد. اسکریپت DNS را هم بررسی می‌کند و سایت‌های پروکسی دیگران را مشخص می‌کند.

## دانلود

[آرشیو ZIP](https://github.com/nekogs/RealiTLScanner-Windows-PowerShell/archive/refs/heads/main.zip) را دانلود کنید (یا در همین صفحه Code ← Download ZIP) و در هر پوشه‌ای از حالت فشرده خارج کنید. داخل آن `RealiTLScanner.ps1` و `RealiTLScanner.cmd` است. چیز دیگری لازم نیست: Windows PowerShell 5.1 در ویندوز 10/11 یا PowerShell 7 کافی است.

## اجرا

ویندوز به‌طور پیش‌فرض فایل‌های `.ps1` دانلودشده را اجرا نمی‌کند، پس اسکریپت را این‌طور اجرا کنید:

```powershell
powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
```

### اجرا با دوبار کلیک

روی `RealiTLScanner.cmd` دوبار کلیک کنید. اسکریپت اجرا می‌شود و یک IP، CIDR یا دامنه برای اسکن می‌پرسد. اسکن IP یا دامنه تا وقتی Ctrl+C را بزنید ادامه دارد. نتایج در `out.csv` کنار اسکریپت ذخیره می‌شود و پنجره تا زدن Enter باز می‌ماند. اگر ویندوز پیام «Windows protected your PC» را نشان داد، روی «More info» و سپس «Run anyway» کلیک کنید.

## کاربرد

بهتر است اسکنر را روی سیستم خودتان اجرا کنید: اجرای آن روی VPS ممکن است باعث علامت‌گذاری سرور شود.

دستورهای زیر در یک پنجرهٔ PowerShell که در پوشهٔ اسکریپت باز شده اجرا می‌شوند. ابتدا یک بار این را در همان پنجره اجرا کنید:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

```powershell
# نمایش راهنما
.\RealiTLScanner.ps1

# اسکن یک IP، CIDR یا دامنه:
.\RealiTLScanner.ps1 -addr 1.2.3.4
# اگر addr یک IP یا دامنه باشد، حالت بی‌پایان خودکار فعال می‌شود (ip، ip-1، ip+1، ... تا Ctrl+C)

# اسکن فهرست اهداف از یک فایل (هر خط یک هدف):
.\RealiTLScanner.ps1 -in in.txt

# جمع‌آوری دامنه‌ها از یک URL و اسکن آن‌ها:
.\RealiTLScanner.ps1 -url https://launchpad.net/ubuntu/+archivemirrors

# پورت برای بررسی، پیش‌فرض: 443
.\RealiTLScanner.ps1 -addr 1.1.1.1 -port 443

# خروجی مفصل، شامل اسکن‌های ناموفق و اهداف نامناسب:
.\RealiTLScanner.ps1 -addr 1.2.3.0/24 -v

# ذخیرهٔ نتایج در فایل، پیش‌فرض: out.csv
.\RealiTLScanner.ps1 -addr www.microsoft.com -out file.csv

# تعداد رشته‌ها (thread)، پیش‌فرض: 2
.\RealiTLScanner.ps1 -addr wiki.ubuntu.com -thread 10

# مهلت هر اسکن، پیش‌فرض: 10 (ثانیه)
.\RealiTLScanner.ps1 -addr 107.172.1.1/16 -timeout 5

# اسکن آدرس‌های IPv6 در کنار IPv4:
.\RealiTLScanner.ps1 -in in.txt -46

# خاموش کردن بررسی DNS دامنهٔ گواهی (به‌طور پیش‌فرض روشن است):
.\RealiTLScanner.ps1 -addr 1.2.3.4 -check-dns=false

# چاپ لاگ‌ها با قالب RealiTLScanner اصلی:
.\RealiTLScanner.ps1 -addr 1.2.3.4 -raw
```

### فعال‌سازی GeoIP

برای نمایش کشور هر IP، پایگاه دادهٔ MaxMind GeoLite2/GeoIP2 Country را با نام `Country.mmdb` در پوشه‌ای که اسکریپت را از آن اجرا می‌کنید قرار دهید. می‌توانید آن را از [اینجا](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb) دانلود کنید.

## حمایت از نویسنده

نویسندهٔ این اسکریپت یک زندانی سیاسی در روسیه است. اگر می‌توانید چیزی برای رامن بپردازید، سپاسگزار می‌شوم!

|           | آدرس                                                                  |
|-----------|-----------------------------------------------------------------------|
| 💵 USDT (ERC-20) | `0x23c23dc5ed6888d9287da95cba454d4889241202` |
| ₿ BTC      | `bc1q7x2ez0atrtgq0qc5n3phszud0d3geuqvzhhhtu` |
