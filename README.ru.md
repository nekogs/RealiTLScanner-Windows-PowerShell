<p dir="auto"><a href="/README.md">English</a> | <a href="/README.fa.md">فارسی</a> | <a href="/README.ar_EG.md">العربية</a> | <a href="/README.zh.md">中文</a> | <a href="/README.es.md">Español</a> | <a href="/README.ru.md">Русский</a> | <a href="/README.tr_TR.md">Türkçe</a></p>

# RealiTLScanner — Windows PowerShell

Порт [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) на PowerShell. Ищет TLS-серверы, которые подходят как `dest` для Xray REALITY: TLS 1.3, ALPN `h2`, в сертификате есть CN и организация издателя. Скрипт проверяет DNS и подсвечивает чужие прокси сайты.

## Скачать

Скачайте [ZIP-архив](https://github.com/nekogs/RealiTLScanner-Windows-PowerShell/releases/latest/download/RealiTLScanner-Windows-PowerShell-main.zip) и распакуйте в любую папку. В архиве `RealiTLScanner.ps1` и `RealiTLScanner.cmd`. Больше ничего не нужно: хватает Windows PowerShell 5.1 из Windows 10/11 или PowerShell 7.

## Запуск

### Способ 1: двойной щелчок по RealiTLScanner.cmd

Дважды щёлкните `RealiTLScanner.cmd`. Он запустит скрипт, и тот спросит IP, CIDR или домен для сканирования. IP или домен сканируется, пока не нажать Ctrl+C. Результат сохраняется в `out.csv` рядом со скриптом, а окно не закрывается, пока не нажать Enter. Если Windows покажет «Система Windows защитила ваш компьютер», нажмите «Подробнее», затем «Выполнить в любом случае».

### Способ 2: из окна PowerShell

Сначала откройте окно PowerShell одним из двух способов:

1. В Проводнике откройте папку со скриптом, зажмите **Shift**, щёлкните правой кнопкой мыши по пустому месту в папке и выберите «Открыть окно PowerShell здесь» (в Windows 11: правая кнопка → «Открыть в Терминале»). Окно откроется сразу в папке со скриптом.
2. Откройте **Пуск**, наберите `PowerShell` и запустите Windows PowerShell. Окно откроется в папке пользователя, поэтому скрипту нужно указать полный путь (см. ниже).

По умолчанию Windows не запускает скачанные `.ps1`, поэтому запускайте скрипт так:

```powershell
powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
```

Если окно открыто не в папке со скриптом, вместо `.\RealiTLScanner.ps1` укажите полный путь к скрипту. Проще всего так: наберите `powershell -ExecutionPolicy Bypass -File ` (с пробелом в конце), перетащите `RealiTLScanner.ps1` из Проводника в окно PowerShell, и Windows вставит путь к файлу. Затем допишите ` -addr 1.2.3.4` и нажмите Enter.

## Использование

Сканер лучше запускать локально: сканирование с VPS может привести к тому, что хостер пометит сервер.

Команды ниже выполняются в окне PowerShell, открытом в папке со скриптом. Сначала один раз выполните в этом окне:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

```powershell
# Показать справку
.\RealiTLScanner.ps1

# Сканировать IP, CIDR или домен:
.\RealiTLScanner.ps1 -addr 1.2.3.4
# Если addr — это IP или домен, бесконечный режим включается сам (ip, ip-1, ip+1, ... до Ctrl+C)

# Сканировать список целей из файла (по одной на строку):
.\RealiTLScanner.ps1 -in in.txt

# Собрать домены со страницы и просканировать их:
.\RealiTLScanner.ps1 -url https://launchpad.net/ubuntu/+archivemirrors

# Порт для проверки, по умолчанию: 443
.\RealiTLScanner.ps1 -addr 1.1.1.1 -port 443

# Подробный вывод, включая неудачные проверки и неподходящие адреса:
.\RealiTLScanner.ps1 -addr 1.2.3.0/24 -v

# Сохранить результат в файл, по умолчанию: out.csv
.\RealiTLScanner.ps1 -addr www.microsoft.com -out file.csv

# Число потоков, по умолчанию: 2
.\RealiTLScanner.ps1 -addr wiki.ubuntu.com -thread 10

# Таймаут на одну проверку, по умолчанию: 10 (секунд)
.\RealiTLScanner.ps1 -addr 107.172.1.1/16 -timeout 5

# Сканировать IPv6-адреса вместе с IPv4:
.\RealiTLScanner.ps1 -in in.txt -46

# Отключить проверку DNS домена из сертификата (по умолчанию включена):
.\RealiTLScanner.ps1 -addr 1.2.3.4 -check-dns=false

# Печатать логи в формате оригинального RealiTLScanner:
.\RealiTLScanner.ps1 -addr 1.2.3.4 -raw
```

### GeoIP

Чтобы видеть страну каждого IP, положите базу MaxMind GeoLite2/GeoIP2 Country под именем `Country.mmdb` в папку, из которой запускаете скрипт. Скачать можно [здесь](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb).

## Поддержать автора

Автор скрипта — политический заключённый в РФ. Если у вас есть возможность подкинуть
на дошик — буду благодарен!

|           | Адрес                                                                 |
|-----------|-----------------------------------------------------------------------|
| 💵 USDT (ERC-20) | `0x23c23dc5ed6888d9287da95cba454d4889241202` |
| ₿ BTC      | `bc1q7x2ez0atrtgq0qc5n3phszud0d3geuqvzhhhtu` |
