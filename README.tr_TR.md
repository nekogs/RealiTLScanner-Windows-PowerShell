<p dir="auto"><a href="/README.md">English</a> | <a href="/README.fa.md">فارسی</a> | <a href="/README.ar_EG.md">العربية</a> | <a href="/README.zh.md">中文</a> | <a href="/README.es.md">Español</a> | <a href="/README.ru.md">Русский</a> | <a href="/README.tr_TR.md">Türkçe</a></p>

# RealiTLScanner — Windows PowerShell

[XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) projesinin PowerShell portu. Xray REALITY için `dest` olarak uygun TLS sunucularını bulur: TLS 1.3, ALPN `h2` ve CN ile yayıncı kuruluş içeren bir sertifika. Betik ayrıca DNS kontrolü yapar ve başkalarına ait proxy sitelerini vurgular.

## İndirme

[ZIP arşivini](https://github.com/nekogs/RealiTLScanner-Windows-PowerShell/archive/refs/heads/main.zip) indirin (veya bu sayfada Code → Download ZIP) ve herhangi bir klasöre çıkarın. İçinde `RealiTLScanner.ps1` ve `RealiTLScanner.cmd` bulunur. Başka bir şey gerekmez: Windows 10/11 ile gelen Windows PowerShell 5.1 veya PowerShell 7 yeterlidir.

## Çalıştırma

Windows varsayılan olarak indirilen `.ps1` dosyalarını çalıştırmaz, bu yüzden betiği şöyle başlatın:

```powershell
powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
```

### Çift tıklayarak çalıştırma

`RealiTLScanner.cmd` dosyasına çift tıklayın. Betiği başlatır ve taranacak bir IP, CIDR veya alan adı sorar. IP veya alan adı, Ctrl+C tuşlarına basana kadar taranır. Sonuçlar betiğin yanındaki `out.csv` dosyasına kaydedilir ve pencere Enter tuşuna basana kadar açık kalır. Windows "Windows bilgisayarınızı korudu" uyarısı gösterirse "Ek bilgi"ye, ardından "Yine de çalıştır"a tıklayın.

## Kullanım

Tarayıcıyı yerel olarak çalıştırmanız önerilir: bir VPS üzerinde çalıştırmak sunucunun işaretlenmesine yol açabilir.

Aşağıdaki komutlar, betik klasöründe açılmış bir PowerShell penceresinde çalıştırılır. Önce o pencerede bunu bir kez çalıştırın:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

```powershell
# Yardımı göster
.\RealiTLScanner.ps1

# Bir IP, IP CIDR veya alan adını tara:
.\RealiTLScanner.ps1 -addr 1.2.3.4
# Not: addr bir IP veya alan adıysa sonsuz mod otomatik olarak açılır (ip, ip-1, ip+1, ... Ctrl+C'ye kadar)

# Bir dosyadaki hedef listesini tara (her satırda bir hedef):
.\RealiTLScanner.ps1 -in in.txt

# Bir URL'den alan adlarını topla ve tara:
.\RealiTLScanner.ps1 -url https://launchpad.net/ubuntu/+archivemirrors

# Taranacak port, varsayılan: 443
.\RealiTLScanner.ps1 -addr 1.1.1.1 -port 443

# Ayrıntılı çıktı, başarısız taramalar ve uygun olmayan hedefler dahil:
.\RealiTLScanner.ps1 -addr 1.2.3.0/24 -v

# Sonuçları bir dosyaya kaydet, varsayılan: out.csv
.\RealiTLScanner.ps1 -addr www.microsoft.com -out file.csv

# İş parçacığı (thread) sayısı, varsayılan: 2
.\RealiTLScanner.ps1 -addr wiki.ubuntu.com -thread 10

# Her tarama için zaman aşımı, varsayılan: 10 (saniye)
.\RealiTLScanner.ps1 -addr 107.172.1.1/16 -timeout 5

# IPv4'ün yanında IPv6 adreslerini de tara:
.\RealiTLScanner.ps1 -in in.txt -46

# Sertifika alan adının DNS kontrolünü kapat (varsayılan olarak açık):
.\RealiTLScanner.ps1 -addr 1.2.3.4 -check-dns=false

# Günlükleri orijinal RealiTLScanner biçiminde yazdır:
.\RealiTLScanner.ps1 -addr 1.2.3.4 -raw
```

### GeoIP'yi etkinleştirme

Her IP'nin ülkesini görmek için `Country.mmdb` adlı bir MaxMind GeoLite2/GeoIP2 Country veritabanını betiği çalıştırdığınız klasöre koyun. [Buradan](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb) indirebilirsiniz.

## Yazara destek

Betiklerin yazarı Rusya'da siyasi bir mahkûmdur. Hazır erişteneye katkıda
bulunabilecekseniz minnettar olurum!

|           | Adres                                                                |
|-----------|----------------------------------------------------------------------|
| 💵 USDT (ERC-20) | `0x23c23dc5ed6888d9287da95cba454d4889241202` |
| ₿ BTC      | `bc1q7x2ez0atrtgq0qc5n3phszud0d3geuqvzhhhtu` |
