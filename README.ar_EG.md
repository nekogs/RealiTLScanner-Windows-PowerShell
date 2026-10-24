<p dir="auto"><a href="/README.md">English</a> | <a href="/README.fa.md">فارسی</a> | <a href="/README.ar_EG.md">العربية</a> | <a href="/README.zh.md">中文</a> | <a href="/README.es.md">Español</a> | <a href="/README.ru.md">Русский</a> | <a href="/README.tr_TR.md">Türkçe</a></p>

# RealiTLScanner — Windows PowerShell

منفذ [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) إلى PowerShell. يبحث عن خوادم TLS المناسبة لاستخدامها كـ `dest` في Xray REALITY: ‏TLS 1.3 و ALPN `h2` وشهادة تحتوي على CN واسم المنظمة المُصدِرة. يتحقق السكربت أيضًا من DNS ويُميّز مواقع البروكسي التابعة لآخرين.

## التنزيل

نزّل `RealiTLScanner-windows.zip` من [Releases](https://github.com/nekogs/RealiTLScanner-Windows-PowerShell/releases/latest) وفُك ضغطه في أي مجلد. يحتوي على `RealiTLScanner.ps1` و `RealiTLScanner.cmd`. لا حاجة لأي شيء آخر: يكفي Windows PowerShell 5.1 المضمّن في Windows 10/11 أو PowerShell 7.

## التشغيل

لا يشغّل Windows ملفات `.ps1` المُنزّلة افتراضيًا، لذا شغّل السكربت هكذا:

```powershell
powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
```

### التشغيل بنقرة مزدوجة

انقر نقرًا مزدوجًا على `RealiTLScanner.cmd`. سيبدأ السكربت ويطلب عنوان IP أو CIDR أو نطاقًا للفحص. يستمر فحص IP أو النطاق حتى تضغط Ctrl+C. تُحفظ النتائج في `out.csv` بجانب السكربت، وتبقى النافذة مفتوحة حتى تضغط Enter. إذا ظهرت رسالة «Windows protected your PC»، فانقر «More info» ثم «Run anyway».

## الاستخدام

يُنصح بتشغيل الماسح محليًا: قد يؤدي تشغيله على VPS إلى وضع علامة على الخادم.

تُنفَّذ الأوامر أدناه في نافذة PowerShell مفتوحة في مجلد السكربت. نفّذ هذا الأمر مرة واحدة في تلك النافذة أولًا:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

```powershell
# عرض المساعدة
.\RealiTLScanner.ps1

# فحص عنوان IP أو CIDR أو نطاق:
.\RealiTLScanner.ps1 -addr 1.2.3.4
# إذا كان addr عنوان IP أو نطاقًا، يُفعَّل الوضع اللانهائي تلقائيًا (ip، ip-1، ip+1، ... حتى Ctrl+C)

# فحص قائمة أهداف من ملف (هدف في كل سطر):
.\RealiTLScanner.ps1 -in in.txt

# جمع النطاقات من رابط URL وفحصها:
.\RealiTLScanner.ps1 -url https://launchpad.net/ubuntu/+archivemirrors

# المنفذ المراد فحصه، الافتراضي: 443
.\RealiTLScanner.ps1 -addr 1.1.1.1 -port 443

# إخراج مفصل يشمل عمليات الفحص الفاشلة والأهداف غير المناسبة:
.\RealiTLScanner.ps1 -addr 1.2.3.0/24 -v

# حفظ النتائج في ملف، الافتراضي: out.csv
.\RealiTLScanner.ps1 -addr www.microsoft.com -out file.csv

# عدد الخيوط (threads)، الافتراضي: 2
.\RealiTLScanner.ps1 -addr wiki.ubuntu.com -thread 10

# مهلة كل فحص، الافتراضي: 10 (ثوانٍ)
.\RealiTLScanner.ps1 -addr 107.172.1.1/16 -timeout 5

# فحص عناوين IPv6 إلى جانب IPv4:
.\RealiTLScanner.ps1 -in in.txt -46

# إيقاف فحص DNS لنطاق الشهادة (مُفعّل افتراضيًا):
.\RealiTLScanner.ps1 -addr 1.2.3.4 -check-dns=false

# طباعة السجلات بتنسيق RealiTLScanner الأصلي:
.\RealiTLScanner.ps1 -addr 1.2.3.4 -raw
```

### تفعيل GeoIP

لعرض دولة كل عنوان IP، ضع قاعدة بيانات MaxMind GeoLite2/GeoIP2 Country باسم `Country.mmdb` في المجلد الذي تشغّل منه السكربت. يمكنك تنزيلها من [هنا](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb).

## دعم المؤلف

مؤلف هذا السكربت سجين رأي في روسيا. إذا كانت لديك إمكانية المساهمة بثمن بعض
النودلز سريعة التحضير، فسأكون ممتنًا!

|           | العنوان                                                              |
|-----------|----------------------------------------------------------------------|
| 💵 USDT (ERC-20) | `0x23c23dc5ed6888d9287da95cba454d4889241202` |
| ₿ BTC      | `bc1q7x2ez0atrtgq0qc5n3phszud0d3geuqvzhhhtu` |
