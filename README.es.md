<p dir="auto"><a href="/README.md">English</a> | <a href="/README.fa.md">فارسی</a> | <a href="/README.ar_EG.md">العربية</a> | <a href="/README.zh.md">中文</a> | <a href="/README.es.md">Español</a> | <a href="/README.ru.md">Русский</a> | <a href="/README.tr_TR.md">Türkçe</a></p>

# RealiTLScanner — Windows PowerShell

Port de [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) a PowerShell. Busca servidores TLS que sirvan como `dest` para Xray REALITY: TLS 1.3, ALPN `h2` y un certificado con CN y organización emisora. El script también comprueba el DNS y resalta los sitios proxy de terceros.

## Descarga

Descarga `RealiTLScanner-windows.zip` desde [Releases](https://github.com/nekogs/RealiTLScanner-Windows-PowerShell/releases/latest) y descomprímelo en cualquier carpeta. Contiene `RealiTLScanner.ps1` y `RealiTLScanner.cmd`. No hace falta nada más: basta con Windows PowerShell 5.1 de Windows 10/11 o PowerShell 7.

## Ejecución

Por defecto Windows no ejecuta archivos `.ps1` descargados, así que inicia el script así:

```powershell
powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
```

### Ejecutar con doble clic

Haz doble clic en `RealiTLScanner.cmd`. Inicia el script, que pide una IP, un CIDR o un dominio para escanear. Una IP o un dominio se escanea hasta que pulses Ctrl+C. Los resultados se guardan en `out.csv` junto al script y la ventana permanece abierta hasta que pulses Enter. Si Windows muestra «Windows protegió su PC», haz clic en «Más información» y luego en «Ejecutar de todas formas».

## Uso

Se recomienda ejecutar el escáner en local: hacerlo desde un VPS puede hacer que marquen el servidor.

Los comandos siguientes se ejecutan en una ventana de PowerShell abierta en la carpeta del script. Primero ejecuta esto una vez en esa ventana:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

```powershell
# Mostrar la ayuda
.\RealiTLScanner.ps1

# Escanear una IP, un CIDR o un dominio:
.\RealiTLScanner.ps1 -addr 1.2.3.4
# Nota: si addr es una IP o un dominio, el modo infinito se activa solo (ip, ip-1, ip+1, ... hasta Ctrl+C)

# Escanear una lista de objetivos desde un archivo (uno por línea):
.\RealiTLScanner.ps1 -in in.txt

# Recopilar dominios de una URL y escanearlos:
.\RealiTLScanner.ps1 -url https://launchpad.net/ubuntu/+archivemirrors

# Puerto a comprobar, por defecto: 443
.\RealiTLScanner.ps1 -addr 1.1.1.1 -port 443

# Salida detallada, incluidos los escaneos fallidos y los objetivos no aptos:
.\RealiTLScanner.ps1 -addr 1.2.3.0/24 -v

# Guardar los resultados en un archivo, por defecto: out.csv
.\RealiTLScanner.ps1 -addr www.microsoft.com -out file.csv

# Número de hilos, por defecto: 2
.\RealiTLScanner.ps1 -addr wiki.ubuntu.com -thread 10

# Tiempo de espera de cada escaneo, por defecto: 10 (segundos)
.\RealiTLScanner.ps1 -addr 107.172.1.1/16 -timeout 5

# Escanear también direcciones IPv6 además de IPv4:
.\RealiTLScanner.ps1 -in in.txt -46

# Desactivar la comprobación DNS del dominio del certificado (activada por defecto):
.\RealiTLScanner.ps1 -addr 1.2.3.4 -check-dns=false

# Mostrar los registros en el formato del RealiTLScanner original:
.\RealiTLScanner.ps1 -addr 1.2.3.4 -raw
```

### Activar GeoIP

Para ver el país de cada IP, coloca una base de datos MaxMind GeoLite2/GeoIP2 Country llamada `Country.mmdb` en la carpeta desde la que ejecutas el script. Puedes descargarla [aquí](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb).

## Apoyar al autor

El autor del script es un preso político en Rusia. Si puede aportar algo para comprar
fideos instantáneos, ¡le estaré muy agradecido!

|           | Dirección                                                              |
|-----------|-----------------------------------------------------------------------|
| 💵 USDT (ERC-20) | `0x23c23dc5ed6888d9287da95cba454d4889241202` |
| ₿ BTC      | `bc1q7x2ez0atrtgq0qc5n3phszud0d3geuqvzhhhtu` |
