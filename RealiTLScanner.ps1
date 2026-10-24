<#
RealiTLScanner.ps1 - a PowerShell port of XTLS/RealiTLScanner
(https://github.com/XTLS/RealiTLScanner).

Finds TLS servers that suit Xray REALITY as "dest": TLS 1.3 + ALPN h2 + a
certificate with a CN and an issuer organization. The command line, the log
lines and the CSV are the same as in the Go original.

Needs nothing but Windows PowerShell 5.1 (built into Windows 10/11) or
PowerShell 7. Windows' own TLS stack cannot report ALPN/curves to PowerShell
5.1, so the script carries a small TLS client of its own, written in C# and
compiled on the fly by Add-Type.

Usage (same flags as the original):
  powershell -ExecutionPolicy Bypass -File .\RealiTLScanner.ps1 -addr 1.2.3.4
  .\RealiTLScanner.ps1 -in in.txt -thread 10 -v
#>

$ErrorActionPreference = 'Stop'

$source = @'
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace RealiTLScannerPS1
{
    // ------------------------------------------------------------------ targets
    public class Target
    {
        public string Type; // ip, cidr or domain
        public byte[] Ip;   // 16 bytes, IPv4 kept IPv4-mapped like Go's net.IP
        public string Origin;
    }

    public class FlagError : Exception
    {
        public int Code;
        public FlagError(string msg, int code) : base(msg) { Code = code; }
    }

    public static class Scanner
    {
        static string addr, inFile, outFile, url;
        static long port, thread, timeout;
        static bool verbose, enableIPv6, raw, pretty, colors, checkDns = true;
        static int checkedCount, foundCount, proxyCount;
        static string prog, cwd;

        static readonly object logLock = new object();
        static TextWriter csv;
        static Geo geo;
        static volatile bool stopping;
        static readonly ConcurrentDictionary<Socket, byte> sockets = new ConcurrentDictionary<Socket, byte>();

        // ------------------------------------------------------------- logging
        // Mimics Go's log/slog TextHandler: time=... level=INFO msg="..." k=v

        public static string Now()
        {
            DateTimeOffset t = DateTimeOffset.Now;
            string s = t.ToString("yyyy-MM-dd'T'HH:mm:ss.fff", CultureInfo.InvariantCulture);
            TimeSpan o = t.Offset;
            if (o == TimeSpan.Zero) return s + "Z";
            string sign = o < TimeSpan.Zero ? "-" : "+";
            return s + sign + Math.Abs(o.Hours).ToString("00", CultureInfo.InvariantCulture) + ":" +
                Math.Abs(o.Minutes).ToString("00", CultureInfo.InvariantCulture);
        }

        static bool NeedsQuoting(string v)
        {
            if (v.Length == 0) return true;
            foreach (char c in v)
            {
                if (c == ' ' || c == '=' || c == '"' || c < 0x20) return true;
                if (c >= 0x80 && (char.IsWhiteSpace(c) || char.IsControl(c))) return true;
            }
            return false;
        }

        static string Quote(string v)
        {
            if (!NeedsQuoting(v)) return v;
            StringBuilder b = new StringBuilder("\"");
            foreach (char c in v)
            {
                switch (c)
                {
                    case '\\': b.Append("\\\\"); break;
                    case '"': b.Append("\\\""); break;
                    case '\n': b.Append("\\n"); break;
                    case '\r': b.Append("\\r"); break;
                    case '\t': b.Append("\\t"); break;
                    default:
                        if (c < 0x20) b.Append("\\x" + ((int)c).ToString("x2", CultureInfo.InvariantCulture));
                        else b.Append(c);
                        break;
                }
            }
            return b.Append('"').ToString();
        }

        public static void Log(string level, string msg, params string[] kv)
        {
            if (level == "DEBUG" && !verbose) return;
            if (stopping) return;
            if (pretty) { PrettyLog(level, msg, kv); return; }
            StringBuilder sb = new StringBuilder();
            sb.Append("time=").Append(Now()).Append(" level=").Append(level).Append(" msg=").Append(Quote(msg));
            for (int i = 0; i + 1 < kv.Length; i += 2)
                if (kv[i] != null) sb.Append(' ').Append(kv[i]).Append('=').Append(Quote(kv[i + 1] ?? ""));
            lock (logLock)
            {
                Console.Out.WriteLine(sb.ToString());
                Console.Out.Flush();
            }
        }

        // ------------------------------------------------------- pretty output
        // Human-friendly rendering of the same events, used on a console unless -raw.

        static string gOk = "+", gSkip = "-", gFail = "x", gDot = "|", gEll = "~", gProxy = "!", gArrow = "->";

        static void PrettyInit()
        {
            colors = string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NO_COLOR"));
            if (Console.OutputEncoding.CodePage == 65001)
            {
                gOk = "\u2714"; gSkip = "\u00b7"; gFail = "\u2717"; gDot = "\u00b7"; gEll = "\u2026"; gProxy = "\u21aa"; gArrow = "\u2192";
            }
        }

        static string Fit(string t, int w)
        {
            if (t.Length > w) return t.Substring(0, w - 1) + gEll;
            return t.PadRight(w);
        }

        class Seg
        {
            public string Text; public ConsoleColor? Color;
            public Seg(string t, ConsoleColor? c) { Text = t; Color = c; }
        }

        static Seg S(string t) { return new Seg(t, null); }
        static Seg S(string t, ConsoleColor c) { return new Seg(t, c); }

        static void Write(params Seg[] segs)
        {
            lock (logLock)
            {
                ClearStatus();
                foreach (Seg g in segs)
                {
                    if (colors && g.Color.HasValue) Console.ForegroundColor = g.Color.Value;
                    Console.Out.Write(g.Text);
                    if (colors && g.Color.HasValue) Console.ResetColor();
                }
                Console.Out.WriteLine();
                Console.Out.Flush();
            }
        }

        // Live status line under the table, redrawn in place while the scan runs,
        // so that a long stretch without results does not look like a hang.
        static int statusLen; // length of the status line on screen, 0 when there is none
        static volatile string current = "";
        static Thread ticker;
        static readonly ManualResetEvent tickerStop = new ManualResetEvent(false);

        static void ClearStatus() // under logLock
        {
            if (statusLen == 0) return;
            Console.Out.Write("\r" + new string(' ', statusLen) + "\r");
            Console.Out.Flush();
            statusLen = 0;
        }

        static string Elapsed(TimeSpan t)
        {
            int s = (int)t.TotalSeconds;
            if (s >= 3600) return (s / 3600) + "h" + (s % 3600 / 60) + "m" + (s % 60) + "s";
            if (s >= 60) return (s / 60) + "m" + (s % 60) + "s";
            return s + "s";
        }

        static void StatusLoop(object state)
        {
            Stopwatch sw = (Stopwatch)state;
            string[] frames = { "|", "/", "-", "\\" };
            int i = 0;
            do
            {
                lock (logLock)
                {
                    if (stopping) continue;
                    string frame = frames[i++ % frames.Length];
                    string counts = " scanning " + gDot + " checked " + checkedCount + " " + gDot + " ";
                    string found = "suitable " + foundCount;
                    string proxies = checkDns ? "proxy-site " + proxyCount : "";
                    string tail = " " + gDot + " " + Elapsed(sw.Elapsed);
                    string cur = current;
                    if (cur.Length > 0) tail += " " + gDot + " now " + cur;
                    int width = 0;
                    try { width = Console.WindowWidth - 1; } catch (Exception) { }
                    int len = 2 + frame.Length + counts.Length + found.Length + (checkDns ? 3 + proxies.Length : 0) + tail.Length;
                    if (width > 0 && len > width && cur.Length > 0)
                    {
                        tail = " " + gDot + " " + Elapsed(sw.Elapsed);
                        len -= 7 + cur.Length;
                    }
                    if (width > 0 && len > width) continue; // a tiny window: better nothing than a wrapped line
                    Console.Out.Write("\r  ");
                    Seg[] segs = {
                        S(frame, ConsoleColor.Cyan), S(counts, ConsoleColor.DarkGray), S(found, ConsoleColor.Green),
                        S(checkDns ? " " + gDot + " " : "", ConsoleColor.DarkGray), S(proxies, ConsoleColor.Yellow),
                        S(tail, ConsoleColor.DarkGray) };
                    foreach (Seg g in segs)
                    {
                        if (colors && g.Color.HasValue) Console.ForegroundColor = g.Color.Value;
                        Console.Out.Write(g.Text);
                        if (colors && g.Color.HasValue) Console.ResetColor();
                    }
                    if (len < statusLen) Console.Out.Write(new string(' ', statusLen - len) + "\r");
                    Console.Out.Flush();
                    statusLen = Math.Max(len, statusLen);
                }
            } while (!tickerStop.WaitOne(500));
        }

        static void StartStatus(Stopwatch sw)
        {
            tickerStop.Reset();
            ticker = new Thread(StatusLoop);
            ticker.IsBackground = true;
            ticker.Start(sw);
        }

        static void StopStatus()
        {
            if (ticker == null) return;
            tickerStop.Set();
            ticker.Join();
            ticker = null;
            lock (logLock) ClearStatus();
        }

        static void PrettyLog(string level, string msg, string[] kv)
        {
            Dictionary<string, string> a = new Dictionary<string, string>();
            for (int i = 0; i + 1 < kv.Length; i += 2) if (kv[i] != null) a[kv[i]] = kv[i + 1] ?? "";
            ConsoleColor dim = ConsoleColor.DarkGray;
            switch (msg)
            {
                case "Connected to target":
                    {
                        string origin = a["origin"] != a["ip"] && a["origin"].IndexOf('/') < 0 ? a["origin"] : "";
                        string ip = Fit(a["ip"], 15);
                        string dns;
                        if (a["feasible"] == "true" && a.TryGetValue("dns", out dns) && dns != "ok")
                        {
                            // suitable by TLS, but the certificate's domain lives elsewhere:
                            // this IP only relays someone else's site (a proxy / REALITY server)
                            Interlocked.Increment(ref proxyCount);
                            string where = dns == "proxy:" ? "(domain does not resolve)" : gArrow + " " + dns.Substring(6);
                            Write(S("  "), S(gProxy, ConsoleColor.Yellow), S(" "), S(ip, ConsoleColor.White), S("  "),
                                S(Fit(a["cert-domain"], 30), ConsoleColor.Yellow), S("  " + Fit(a["cert-issuer"], 24) + "  " + a["tls"] + "  " +
                                Fit(a["alpn"], 4) + "  " + Fit(a["curve"], 14) + "  " + a["geo"].PadRight(4) + "  "),
                                S("proxy-site", ConsoleColor.Yellow), S(" " + where, dim),
                                S(origin.Length > 0 ? " (" + origin + ")" : "", dim));
                        }
                        else if (a["feasible"] == "true")
                        {
                            Interlocked.Increment(ref foundCount);
                            bool checkedDns = a.ContainsKey("dns");
                            Write(S("  "), S(gOk, ConsoleColor.Green), S(" "), S(ip, ConsoleColor.White), S("  "),
                                S(Fit(a["cert-domain"], 30), ConsoleColor.Green), S("  " + Fit(a["cert-issuer"], 24) + "  " + a["tls"] + "  " +
                                Fit(a["alpn"], 4) + "  " + Fit(a["curve"], 14) + "  " + (checkedDns ? a["geo"].PadRight(4) + "  " : a["geo"])),
                                S(checkedDns ? "matches IP" : "", ConsoleColor.Green),
                                S(origin.Length > 0 ? " (" + origin + ")" : "", dim));
                        }
                        else
                        {
                            string why = a["tls"] != "TLS 1.3" ? a["tls"]
                                : a["alpn"] != "h2" ? "ALPN " + (a["alpn"].Length > 0 ? a["alpn"] : "none")
                                : a["cert-domain"].Length == 0 ? "no CN in certificate" : "no issuer organization";
                            Write(S("  " + gSkip + " " + ip + "  " + Fit(a["cert-domain"], 30) + "  not suitable: " + why +
                                (origin.Length > 0 ? " (" + origin + ")" : ""), dim));
                        }
                        return;
                    }
                case "Cannot dial":
                    Write(S("  " + gFail + " " + Fit(a["target"], 21) + "  no TCP connection", dim));
                    return;
                case "TLS handshake failed":
                    Write(S("  " + gFail + " " + Fit(a["target"], 21) + "  TLS handshake failed", dim));
                    return;
                case "Failed to get IP from the origin":
                    Write(S("  " + gFail + " " + Fit(a["origin"], 21) + "  DNS lookup failed", dim));
                    return;
                case "Error reading geo":
                    return;
                case "Enable infinite mode":
                    Write(S("Infinite mode: walking outward from " + a["init"] + ", press Ctrl+C to stop", dim));
                    return;
                case "Enabled GeoIP":
                    Write(S("GeoIP: on", dim));
                    return;
                case "Cannot open Country.mmdb":
                    Write(S("GeoIP: off (" + a["err"] + ")", dim));
                    return;
                case "Fetching url...":
                    Write(S("Fetching " + url + " ..."));
                    return;
                case "Parsed domains":
                    Write(S("Found " + a["count"] + " domains on the page"));
                    return;
                case "Not a valid IP, IP CIDR or domain":
                    if (level == "ERROR") Write(S("Error: \"" + a["addr"] + "\" is not an IP, CIDR or resolvable domain", ConsoleColor.Red));
                    else Write(S("Skipped \"" + a["line"] + "\": not an IP, CIDR or domain", ConsoleColor.Yellow));
                    return;
                case "Invalid cidr":
                    Write(S("Skipped \"" + a["cidr"] + "\": invalid CIDR prefix", ConsoleColor.Yellow));
                    return;
                case "Started all scanning threads":
                    {
                        string target = addr != "" ? "-addr " + addr : inFile != "" ? "-in " + inFile : "-url " + url;
                        Write(S("RealiTLScanner", ConsoleColor.Cyan), S(" " + gDot + " " + target + " " + gDot + " port " + port + " " + gDot + " " +
                            thread + " threads " + gDot + " timeout " + timeout + "s " + gDot + " DNS check: " + (checkDns ? "on" : "off") + " " + gDot + " CSV: " + (outFile != "" ? outFile : "off")));
                        Write(S("    " + Fit("IP", 15) + "  " + Fit("CERT DOMAIN", 30) + "  " + Fit("ISSUER", 24) + "  TLS      ALPN  " + Fit("CURVE", 14) + "  GEO" + (checkDns ? "   DNS CHECK" : ""), dim));
                        return;
                    }
                case "Scanning completed":
                case "Scanning stopped":
                    {
                        Console.Out.WriteLine();
                        string tail = outFile != "" && foundCount + proxyCount > 0 ? " " + gDot + " saved to " + outFile : "";
                        Write(S(msg == "Scanning stopped" ? "Stopped" : "Done", ConsoleColor.White),
                            S(" in " + a["elapsed"] + " " + gDot + " checked " + checkedCount + " " + gDot + " "),
                            S("suitable " + foundCount, ConsoleColor.Green),
                            S(checkDns ? " " + gDot + " " : ""), S(checkDns ? "proxy-site " + proxyCount : "", ConsoleColor.Yellow), S(tail));
                        return;
                    }
            }
            string text = msg == "You must specify and only specify one of `addr`, `in`, or `url`" ? "specify exactly one of -addr, -in or -url" : msg;
            foreach (KeyValuePair<string, string> p in a) text += " " + p.Key + ": " + p.Value;
            if (level == "ERROR") Write(S("Error: " + text, ConsoleColor.Red));
            else if (level == "WARN") Write(S("Warning: " + text, ConsoleColor.Yellow));
            else Write(S(text, dim));
        }

        // Go's time.Duration.String()
        static string GoDuration(long ticks)
        {
            long ns = ticks * 100;
            if (ns == 0) return "0s";
            if (ns < 1000000000L)
            {
                if (ns < 1000) return ns + "ns";
                if (ns < 1000000) return Frac(ns / 1000, ns % 1000, 3) + "\u00b5s";
                return Frac(ns / 1000000, ns % 1000000, 6) + "ms";
            }
            long s = ns / 1000000000L;
            string f = Frac(s % 60, ns % 1000000000L, 9) + "s";
            long h = s / 3600, m = s % 3600 / 60;
            string r = "";
            if (h > 0) r += h + "h";
            if (h > 0 || m > 0) r += m + "m";
            return r + f;
        }

        static string Frac(long whole, long frac, int digits)
        {
            string f = frac.ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0').TrimEnd('0');
            return whole.ToString(CultureInfo.InvariantCulture) + (f.Length > 0 ? "." + f : "");
        }

        // --------------------------------------------------------------- flags
        // Mimics Go's flag package.

        const string Defaults =
            "  -46\n" +
            "    \tEnable IPv6 in additional to IPv4\n" +
            "  -addr string\n" +
            "    \tSpecify an IP, IP CIDR or domain to scan\n" +
            "  -check-dns\n" +
            "    \tResolve the certificate domain and mark the result as proxy-site when it does not point to the scanned IP or its /24 (terminal output only) (default true)\n" +
            "  -in string\n" +
            "    \tSpecify a file that contains multiple IPs, IP CIDRs or domains to scan, divided by line break\n" +
            "  -out string\n" +
            "    \tOutput file to store the result (default \"out.csv\")\n" +
            "  -port int\n" +
            "    \tSpecify a HTTPS port to check (default 443)\n" +
            "  -raw\n" +
            "    \tPrint logs in the original RealiTLScanner format (always used when the output is not a console)\n" +
            "  -thread int\n" +
            "    \tCount of concurrent tasks (default 2)\n" +
            "  -timeout int\n" +
            "    \tTimeout for every check (default 10)\n" +
            "  -url string\n" +
            "    \tCrawl the domain list from a URL, e.g. https://launchpad.net/ubuntu/+archivemirrors\n" +
            "  -v\tVerbose output\n";

        static void Usage()
        {
            Console.Error.Write("Usage of " + prog + ":\n" + Defaults);
        }

        static bool ParseBool(string s, out bool v)
        {
            switch (s)
            {
                case "1": case "t": case "T": case "TRUE": case "true": case "True": v = true; return true;
                case "0": case "f": case "F": case "FALSE": case "false": case "False": v = false; return true;
            }
            v = false;
            return false;
        }

        // Go's strconv.ParseInt(s, 0, 64). 0 = ok, 1 = syntax error, 2 = out of range.
        static int ParseInt(string s, out long v)
        {
            v = 0;
            bool neg = false;
            if (s.Length > 0 && (s[0] == '+' || s[0] == '-')) { neg = s[0] == '-'; s = s.Substring(1); }
            int b = 10;
            string body = s;
            if (s.Length >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { b = 16; body = s.Substring(2); }
            else if (s.Length >= 2 && s[0] == '0' && (s[1] == 'o' || s[1] == 'O')) { b = 8; body = s.Substring(2); }
            else if (s.Length >= 2 && s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) { b = 2; body = s.Substring(2); }
            else if (s.Length >= 2 && s[0] == '0') { b = 8; body = s.Substring(1); }
            string digit = b == 16 ? "[0-9a-fA-F]" : b == 8 ? "[0-7]" : b == 2 ? "[01]" : "[0-9]";
            string pat = b == 10 ? "^" + digit + "+(_" + digit + "+)*$" : "^_?" + digit + "+(_" + digit + "+)*$";
            if (!Regex.IsMatch(body, pat)) return 1;
            BigInteger n = BigInteger.Zero;
            foreach (char c in body.Replace("_", ""))
                n = n * b + Convert.ToInt32(c.ToString(), 16);
            if (neg) n = -n;
            if (n > long.MaxValue || n < long.MinValue) return 2;
            v = (long)n;
            return 0;
        }

        static void Fail(string msg)
        {
            throw new FlagError(msg, 2);
        }

        static void ParseFlags(string[] args)
        {
            int i = 0;
            while (i < args.Length)
            {
                string a = args[i];
                if (a.Length < 2 || a[0] != '-') break;
                string name = a.Substring(1);
                if (name[0] == '-')
                {
                    name = name.Substring(1);
                    if (name.Length == 0) { i++; break; } // "--" ends the flags
                }
                if (name.Length == 0 || name[0] == '-' || name[0] == '=') Fail("bad flag syntax: " + a);
                i++;
                bool hasValue = false;
                string value = "";
                int eq = name.IndexOf('=');
                if (eq >= 0) { value = name.Substring(eq + 1); name = name.Substring(0, eq); hasValue = true; }
                switch (name)
                {
                    case "v":
                    case "46":
                    case "raw":
                    case "check-dns":
                        {
                            bool bv = true;
                            if (hasValue && !ParseBool(value, out bv))
                                Fail("invalid boolean value \"" + value + "\" for -" + name + ": parse error");
                            if (name == "v") verbose = bv; else if (name == "46") enableIPv6 = bv; else if (name == "raw") raw = bv; else checkDns = bv;
                            break;
                        }
                    case "addr": case "in": case "out": case "url":
                    case "port": case "thread": case "timeout":
                        {
                            if (!hasValue)
                            {
                                if (i >= args.Length) Fail("flag needs an argument: -" + name);
                                value = args[i++];
                            }
                            if (name == "addr") addr = value;
                            else if (name == "in") inFile = value;
                            else if (name == "out") outFile = value;
                            else if (name == "url") url = value;
                            else
                            {
                                long n;
                                int rc = ParseInt(value, out n);
                                if (rc == 1) Fail("invalid value \"" + value + "\" for flag -" + name + ": parse error");
                                if (rc == 2) Fail("invalid value \"" + value + "\" for flag -" + name + ": value out of range");
                                if (name == "port") port = n; else if (name == "thread") thread = n; else timeout = n;
                            }
                            break;
                        }
                    case "h":
                    case "help":
                        throw new FlagError(null, 0);
                    default:
                        Fail("flag provided but not defined: -" + name);
                        break;
                }
            }
        }

        // ------------------------------------------------------- IP addresses

        static bool ParseIPv4(string s, out uint v)
        {
            v = 0;
            string[] p = s.Split('.');
            if (p.Length != 4) return false;
            foreach (string o in p)
            {
                if (o.Length == 0 || o.Length > 3) return false;
                foreach (char c in o) if (c < '0' || c > '9') return false;
                if (o.Length > 1 && o[0] == '0') return false;
                int n = int.Parse(o, CultureInfo.InvariantCulture);
                if (n > 255) return false;
                v = (v << 8) | (uint)n;
            }
            return true;
        }

        static byte[] Mapped(uint v)
        {
            byte[] b = new byte[16];
            b[10] = 0xff; b[11] = 0xff;
            b[12] = (byte)(v >> 24); b[13] = (byte)(v >> 16); b[14] = (byte)(v >> 8); b[15] = (byte)v;
            return b;
        }

        static bool ParseGroups(string s, List<int> g)
        {
            if (s.Length == 0) return true;
            foreach (string p in s.Split(':'))
            {
                if (p.Length == 0 || p.Length > 4) return false;
                foreach (char c in p) if (Uri.IsHexDigit(c) == false) return false;
                g.Add(int.Parse(p, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
            return true;
        }

        // Go's net.ParseIP
        public static byte[] ParseIP(string s)
        {
            uint v4;
            if (s.IndexOf(':') < 0) return ParseIPv4(s, out v4) ? Mapped(v4) : null;
            if (s.IndexOf('%') >= 0) return null;
            bool hasV4 = false;
            int lastColon = s.LastIndexOf(':');
            string tailV4 = s.Substring(lastColon + 1);
            if (tailV4.IndexOf('.') >= 0)
            {
                if (!ParseIPv4(tailV4, out v4)) return null;
                hasV4 = true;
                s = s.Substring(0, lastColon + 1);
                if (!s.EndsWith("::")) s = s.Substring(0, s.Length - 1);
                if (s.Length == 0) return null;
            }
            else v4 = 0;
            List<int> head = new List<int>(), tail = new List<int>();
            int dc = s.IndexOf("::", StringComparison.Ordinal);
            bool compressed = dc >= 0;
            if (compressed)
            {
                if (s.IndexOf("::", dc + 1, StringComparison.Ordinal) >= 0) return null;
                if (!ParseGroups(s.Substring(0, dc), head) || !ParseGroups(s.Substring(dc + 2), tail)) return null;
            }
            else if (!ParseGroups(s, head)) return null;
            int want = hasV4 ? 6 : 8;
            List<int> all = new List<int>(head);
            if (compressed)
            {
                int fill = want - head.Count - tail.Count;
                if (fill < 1) return null;
                for (int i = 0; i < fill; i++) all.Add(0);
                all.AddRange(tail);
            }
            if (all.Count != want) return null;
            byte[] b = new byte[16];
            for (int i = 0; i < want; i++) { b[2 * i] = (byte)(all[i] >> 8); b[2 * i + 1] = (byte)all[i]; }
            if (hasV4) { byte[] m = Mapped(v4); Array.Copy(m, 12, b, 12, 4); }
            return b;
        }

        static bool IsV4(byte[] b)
        {
            for (int i = 0; i < 10; i++) if (b[i] != 0) return false;
            return b[10] == 0xff && b[11] == 0xff;
        }

        // Go's net.IP.String()
        public static string FormatIP(byte[] b)
        {
            if (IsV4(b)) return b[12] + "." + b[13] + "." + b[14] + "." + b[15];
            int[] g = new int[8];
            for (int i = 0; i < 8; i++) g[i] = (b[2 * i] << 8) | b[2 * i + 1];
            int best = -1, bestLen = 0, cur = -1, curLen = 0;
            for (int i = 0; i < 8; i++)
            {
                if (g[i] == 0)
                {
                    if (cur < 0) { cur = i; curLen = 0; }
                    curLen++;
                    if (curLen > bestLen) { best = cur; bestLen = curLen; }
                }
                else cur = -1;
            }
            if (bestLen < 2) best = -1;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                if (i == best)
                {
                    sb.Append("::");
                    i += bestLen - 1;
                    continue;
                }
                if (sb.Length > 0 && !(sb.Length >= 2 && sb[sb.Length - 1] == ':' && sb[sb.Length - 2] == ':')) sb.Append(':');
                sb.Append(g[i].ToString("x", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        static bool Inc(byte[] b)
        {
            for (int i = 15; i >= 0; i--) if (++b[i] != 0) return true;
            return false;
        }

        static bool Dec(byte[] b)
        {
            for (int i = 15; i >= 0; i--) if (b[i]-- != 0) return true;
            return false;
        }

        // net.ParseCIDR; bad = the netip.ParsePrefix error that Go then logs
        static bool ParseCIDR(string s, out byte[] ip, out int bits, out bool is4, out string bad)
        {
            ip = null; bits = 0; is4 = false; bad = null;
            int slash = s.IndexOf('/');
            if (slash < 0) return false;
            string a = s.Substring(0, slash), m = s.Substring(slash + 1);
            ip = ParseIP(a);
            if (ip == null) return false;
            if (m.Length == 0 || m.Length > 3) return false;
            foreach (char c in m) if (c < '0' || c > '9') return false;
            is4 = a.IndexOf(':') < 0;
            bits = int.Parse(m, CultureInfo.InvariantCulture);
            if (bits > (is4 ? 32 : 128)) return false;
            if (m.Length > 1 && m[0] == '0') bad = "netip.ParsePrefix(\"" + s + "\"): bad bits after slash: \"" + m + "\"";
            if (is4) bits += 96;
            return true;
        }

        static readonly Regex domainRe = new Regex("^[A-Za-z0-9\\-.]+$");

        // Go's Iterate()
        static IEnumerable<Target> IterateLines(IEnumerable<string> lines)
        {
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0) continue;
                byte[] ip = ParseIP(line);
                if (ip != null && (IsV4(ip) || enableIPv6))
                {
                    Target t = new Target();
                    t.Type = "ip"; t.Ip = ip; t.Origin = line;
                    yield return t;
                    continue;
                }
                int bits; bool is4; string bad;
                if (ParseCIDR(line, out ip, out bits, out is4, out bad))
                {
                    if (bad != null) { Log("WARN", "Invalid cidr", "cidr", line, "err", bad); continue; }
                    if (!is4 && !enableIPv6) continue;
                    byte[] net = (byte[])ip.Clone();
                    for (int i = 0; i < 16; i++)
                    {
                        int keep = Math.Max(0, Math.Min(8, bits - 8 * i));
                        net[i] = (byte)(net[i] & (0xff00 >> keep));
                    }
                    byte[] cur = (byte[])net.Clone();
                    while (true)
                    {
                        Target t = new Target();
                        t.Type = "cidr"; t.Ip = (byte[])cur.Clone(); t.Origin = line;
                        yield return t;
                        if (!Inc(cur)) break;
                        bool inside = true;
                        for (int i = 0; i < 16 && inside; i++)
                        {
                            int keep = Math.Max(0, Math.Min(8, bits - 8 * i));
                            if ((cur[i] & (0xff00 >> keep) & 0xff) != net[i]) inside = false;
                        }
                        if (!inside) break;
                    }
                    continue;
                }
                if (domainRe.IsMatch(line))
                {
                    Target t = new Target();
                    t.Type = "domain"; t.Ip = null; t.Origin = line;
                    yield return t;
                    continue;
                }
                Log("WARN", "Not a valid IP, IP CIDR or domain", "line", line);
            }
        }

        // Go's IterateAddr() infinite mode: ip, ip-1, ip+1, ip-2, ip+2, ...
        static IEnumerable<Target> IterateInfinite(byte[] ip, string origin)
        {
            Log("INFO", "Enable infinite mode", "init", FormatIP(ip));
            Target first = new Target();
            first.Type = "ip"; first.Ip = ip; first.Origin = origin;
            yield return first;
            byte[] low = (byte[])ip.Clone(), high = (byte[])ip.Clone();
            bool highOk = true;
            while (true)
            {
                // below "::" Go's big.Int arithmetic gives ::1 again (abs(-1))
                if (!Dec(low)) { low = new byte[16]; low[15] = 1; }
                Target t = new Target();
                t.Type = "ip"; t.Ip = (byte[])low.Clone(); t.Origin = FormatIP(low);
                yield return t;
                if (!highOk) continue;
                if (!Inc(high)) { highOk = false; continue; } // Go panics there
                t = new Target();
                t.Type = "ip"; t.Ip = (byte[])high.Clone(); t.Origin = FormatIP(high);
                yield return t;
            }
        }

        // ----------------------------------------------------------------- DNS

        static byte[] Lookup(string name, out string err)
        {
            err = null;
            string last = name.TrimEnd('.');
            last = last.Substring(last.LastIndexOf('.') + 1);
            bool numeric = last.Length > 0;
            foreach (char c in last) if (c < '0' || c > '9') numeric = false;
            if (numeric) { err = "failed to lookup: lookup " + name + ": no such host"; return null; }
            IPAddress[] list;
            try { list = Dns.GetHostAddresses(name); }
            catch (Exception) { err = "failed to lookup: lookup " + name + ": no such host"; return null; }
            foreach (IPAddress a in list)
            {
                if (a.AddressFamily == AddressFamily.InterNetwork)
                {
                    byte[] v = a.GetAddressBytes();
                    return Mapped(((uint)v[0] << 24) | ((uint)v[1] << 16) | ((uint)v[2] << 8) | v[3]);
                }
                if (a.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    byte[] v = a.GetAddressBytes();
                    if (IsV4(v) || enableIPv6) return v;
                }
            }
            err = list.Length == 0 ? "failed to lookup: lookup " + name + ": no such host" : "no IP found";
            return null;
        }

        // Answers for the DNS check, shared by all workers.
        static readonly ConcurrentDictionary<string, IPAddress[]> dnsCache = new ConcurrentDictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase);

        static IPAddress[] ResolveAll(string name)
        {
            try { return Dns.GetHostAddresses(name); }
            catch (Exception) { return new IPAddress[0]; }
        }

        // "ok", or "proxy:FIRST_ADDRESS" when the certificate's domain resolves
        // somewhere else ("proxy:" when it does not resolve). The domain counts as
        // hosted here when one of its addresses is the scanned IP or sits in the
        // same /24 (IPv4) or /48 (IPv6).
        static string DnsCheck(string certDomain, byte[] ip, string origin)
        {
            bool wildcard = certDomain.StartsWith("*.");
            string name = (wildcard ? certDomain.Substring(2) : certDomain).TrimEnd('.');
            if (string.Equals(name, origin, StringComparison.OrdinalIgnoreCase)) return "ok"; // we got here by resolving it
            IPAddress[] list;
            if (!dnsCache.TryGetValue(name, out list))
            {
                IPAddress literal;
                if (IPAddress.TryParse(name, out literal) && name.IndexOfAny(new char[] { '.', ':' }) >= 0) list = new IPAddress[] { literal };
                else
                {
                    list = ResolveAll(name);
                    if (list.Length == 0 && wildcard) list = ResolveAll("www." + name);
                }
                dnsCache[name] = list;
            }
            bool v4 = IsV4(ip);
            string first = null;
            foreach (IPAddress a in list)
            {
                byte[] b = a.GetAddressBytes();
                if (b.Length == 4) b = Mapped(((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]);
                if (b.Length != 16) continue;
                if (first == null) first = FormatIP(b);
                if (v4 != IsV4(b)) continue;
                int n = v4 ? 15 : 6;
                bool same = true;
                for (int i = 0; i < n; i++) if (b[i] != ip[i]) { same = false; break; }
                if (same) return "ok";
            }
            return "proxy:" + (first ?? "");
        }

        // ---------------------------------------------------------------- scan

        static string CurveName(int id)
        {
            switch (id)
            {
                case 0x001d: return "X25519";
                case 0x0017: return "CurveP256";
                case 0x0018: return "CurveP384";
                case 0x0019: return "CurveP521";
                case 0x11ec: return "X25519MLKEM768";
                case 0x11eb: return "SecP256r1MLKEM768";
                case 0x11ed: return "SecP384r1MLKEM1024";
            }
            return "CurveID(" + id + ")";
        }

        static void ScanTLS(Target host)
        {
            Interlocked.Increment(ref checkedCount);
            byte[] ip = host.Ip;
            if (pretty) current = host.Type == "domain" || ip == null ? host.Origin : FormatIP(ip);
            if (host.Type == "domain")
            {
                string err;
                ip = Lookup(host.Origin, out err);
                if (ip == null)
                {
                    Log("DEBUG", "Failed to get IP from the origin", "origin", host.Origin, "err", err);
                    return;
                }
            }
            string ipStr = FormatIP(ip);
            string hostPort = (ipStr.IndexOf(':') >= 0 ? "[" + ipStr + "]" : ipStr) + ":" + port.ToString(CultureInfo.InvariantCulture);
            IPAddress address = IsV4(ip) ? new IPAddress(new byte[] { ip[12], ip[13], ip[14], ip[15] }) : new IPAddress(ip);
            TlsResult r = Tls.Probe(address, port, host.Type == "domain" ? host.Origin : null, timeout, sockets);
            if (!r.Dialed)
            {
                Log("DEBUG", "Cannot dial", "target", hostPort);
                return;
            }
            if (!r.Ok || r.Certs.Count == 0)
            {
                Log("DEBUG", "TLS handshake failed", "target", hostPort);
                return;
            }
            string tlsVer = r.Version == 0x0304 ? "TLS 1.3" : r.Version == 0x0303 ? "TLS 1.2" : "0x" + r.Version.ToString("X4", CultureInfo.InvariantCulture);
            string curve = CurveName(r.Curve);
            CertInfo first = null, leaf = null;
            int length = 0;
            foreach (byte[] der in r.Certs)
            {
                CertInfo ci = CertInfo.Parse(der);
                length += der.Length;
                if (first == null) { first = ci; leaf = ci; }
                if (ci.HasDNS) leaf = ci;
            }
            string domain = first.CommonName;
            string issuers = string.Join(" | ", first.IssuerOrg.ToArray());
            string certLen = length.ToString(CultureInfo.InvariantCulture) + "(certs count: " + r.Certs.Count.ToString(CultureInfo.InvariantCulture) + ")";
            string geoCode = geo == null ? "N/A" : geo.Country(ip);
            string level = "INFO";
            bool feasible = true;
            if (r.Version != 0x0304 || r.Alpn != "h2" || domain.Length == 0 || issuers.Length == 0)
            {
                level = "DEBUG";
                feasible = false;
            }
            else if (csv != null && !stopping)
            {
                csv.Write(string.Join(",", new string[] {
                    ipStr, host.Origin, tlsVer, r.Alpn, curve, certLen, leaf.Signature, leaf.PublicKey,
                    domain, "\"" + issuers + "\"", geoCode }) + "\n");
            }
            // The DNS check is only shown on the console: -raw logs and the CSV stay as in the original
            string dnsKey = "dns", dnsVal = null;
            if (pretty && checkDns && feasible) dnsVal = DnsCheck(domain, ip, host.Origin);
            else dnsKey = null;
            Log(level, "Connected to target", "feasible", feasible ? "true" : "false",
                "ip", ipStr,
                "origin", host.Origin,
                "tls", tlsVer,
                "alpn", r.Alpn,
                "curve", curve,
                "cert-length", certLen,
                "cert-signature", leaf.Signature,
                "cert-publickey", leaf.PublicKey,
                "cert-domain", domain,
                "cert-issuer", issuers,
                "geo", geoCode,
                dnsKey, dnsVal);
        }

        // ----------------------------------------------------------------- url

        static string Fetch(string u, out string err)
        {
            err = null;
            Match m = Regex.Match(u, "^([A-Za-z][A-Za-z0-9+.-]*):");
            string scheme = m.Success ? m.Groups[1].Value : "";
            if (scheme.ToLowerInvariant() != "http" && scheme.ToLowerInvariant() != "https")
            {
                err = "unsupported protocol scheme \"" + scheme + "\"";
                return null;
            }
            if (!Regex.IsMatch(u, "^[A-Za-z]+://[^/?#]+"))
            {
                err = "http: no Host in request URL";
                return null;
            }
            try
            {
                if (Environment.Version.Major == 4)
                {
                    // .NET Framework: allow TLS 1.2/1.3, older versions default to TLS 1.0
                    try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch (Exception) { }
                    try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288; } catch (Exception) { }
                }
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(u);
                req.UserAgent = "Go-http-client/1.1";
                req.AutomaticDecompression = DecompressionMethods.GZip;
                req.MaximumAutomaticRedirections = 10;
                HttpWebResponse resp;
                try { resp = (HttpWebResponse)req.GetResponse(); }
                catch (WebException we)
                {
                    // Go's http.Get returns the body of non-2xx answers as well
                    if (we.Response == null) throw;
                    resp = (HttpWebResponse)we.Response;
                }
                using (resp)
                using (Stream st = resp.GetResponseStream())
                using (MemoryStream ms = new MemoryStream())
                {
                    st.CopyTo(ms);
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
            catch (Exception e)
            {
                err = e.Message;
                return null;
            }
        }

        // ---------------------------------------------------------------- main

        static void OnCancel(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            stopping = true;
            foreach (Socket s in sockets.Keys)
            {
                try { s.Close(); } catch (Exception) { }
            }
        }

        public static int Run(string[] args, string program, string workdir)
        {
            addr = ""; inFile = ""; outFile = "out.csv"; url = "";
            port = 443; thread = 2; timeout = 10;
            verbose = false; enableIPv6 = false; raw = false; pretty = false; colors = false;
            checkedCount = 0; foundCount = 0; proxyCount = 0; statusLen = 0; current = ""; checkDns = true; dnsCache.Clear();
            prog = program; cwd = workdir;
            stopping = false; csv = null; geo = null;
            ConsoleCancelEventHandler handler = new ConsoleCancelEventHandler(OnCancel);
            Console.CancelKeyPress += handler;
            try
            {
                return RunMain(args);
            }
            finally
            {
                Console.CancelKeyPress -= handler;
                if (csv != null) { try { csv.Flush(); csv.Close(); } catch (Exception) { } }
                if (stopping) Console.Out.Flush();
            }
        }

        // For the interactive prompt: true when Run would accept s as -addr
        public static bool IsValidAddr(string s)
        {
            byte[] ip; int bits; bool is4; string bad, err;
            if (ParseCIDR(s, out ip, out bits, out is4, out bad)) return true;
            return ParseIP(s) != null || Lookup(s, out err) != null;
        }

        static string FullPath(string p)
        {
            return Path.Combine(cwd, p);
        }

        static int RunMain(string[] args)
        {
            try
            {
                ParseFlags(args);
            }
            catch (FlagError e)
            {
                if (e.Message != null && e.Code != 0) Console.Error.WriteLine(e.Message);
                Usage();
                return e.Code;
            }
            pretty = !raw && !Console.IsOutputRedirected;
            if (pretty) PrettyInit();
            int given = 0;
            if (addr != "") given++;
            if (inFile != "") given++;
            if (url != "") given++;
            if (given != 1)
            {
                Log("ERROR", "You must specify and only specify one of `addr`, `in`, or `url`");
                Console.Error.Write(Defaults);
                return 0;
            }
            if (outFile != "")
            {
                try
                {
                    StreamWriter w = new StreamWriter(new FileStream(FullPath(outFile), FileMode.Create, FileAccess.Write, FileShare.ReadWrite), new UTF8Encoding(false));
                    w.AutoFlush = true;
                    w.Write("IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n");
                    csv = TextWriter.Synchronized(w);
                }
                catch (Exception)
                {
                    Log("ERROR", "Error opening file", "path", outFile);
                    return 0;
                }
            }
            IEnumerable<Target> hosts = new Target[0];
            StreamReader reader = null;
            if (addr != "")
            {
                byte[] ip; int bits; bool is4; string bad;
                if (ParseCIDR(addr, out ip, out bits, out is4, out bad))
                    hosts = IterateLines(new string[] { addr });
                else
                {
                    ip = ParseIP(addr);
                    string err;
                    if (ip == null) ip = Lookup(addr, out err);
                    if (ip == null) Log("ERROR", "Not a valid IP, IP CIDR or domain", "addr", addr);
                    else hosts = IterateInfinite(ip, addr);
                }
            }
            else if (inFile != "")
            {
                try { reader = new StreamReader(FullPath(inFile), new UTF8Encoding(false)); }
                catch (Exception)
                {
                    Log("ERROR", "Error reading file", "path", inFile);
                    return 0;
                }
                hosts = IterateLines(ReadLines(reader));
            }
            else
            {
                Log("INFO", "Fetching url...");
                string err;
                string body = Fetch(url, out err);
                if (body == null)
                {
                    Log("ERROR", "Error fetching url", "err", "Get \"" + url + "\": " + err);
                    return 0;
                }
                // Go: regexp (http|https)://(.*?)[/"<>\s]+ , then de-duplicate
                List<string> domains = new List<string>();
                Dictionary<string, bool> seen = new Dictionary<string, bool>();
                foreach (Match m in Regex.Matches(body, "(http|https)://(.*?)[/\"<>\\t\\n\\f\\r ]+"))
                {
                    string d = m.Groups[2].Value;
                    if (seen.ContainsKey(d)) continue;
                    seen[d] = true;
                    domains.Add(d);
                }
                Log("INFO", "Parsed domains", "count", domains.Count.ToString(CultureInfo.InvariantCulture));
                hosts = IterateLines(domains);
            }

            geo = Geo.Open(FullPath("Country.mmdb"));

            if (thread < 0)
            {
                Console.Error.WriteLine("panic: sync: negative WaitGroup counter");
                return 2;
            }
            Stopwatch sw = Stopwatch.StartNew();
            Log("INFO", "Started all scanning threads", "time", Now());
            if (pretty) StartStatus(sw);
            try
            {
                if (thread > 0) RunPool(hosts, (int)Math.Min(thread, 4096));
            }
            finally
            {
                StopStatus();
                if (reader != null) reader.Dispose();
            }
            if (stopping)
            {
                if (pretty)
                {
                    stopping = false; // let the summary through
                    Log("INFO", "Scanning stopped", "time", Now(), "elapsed", GoDuration(sw.Elapsed.Ticks));
                    stopping = true;
                }
                return 130;
            }
            Log("INFO", "Scanning completed", "time", Now(), "elapsed", GoDuration(sw.Elapsed.Ticks));
            return 0;
        }

        static IEnumerable<string> ReadLines(StreamReader r)
        {
            string line;
            while ((line = r.ReadLine()) != null) yield return line;
        }

        static void RunPool(IEnumerable<Target> hosts, int n)
        {
            BlockingCollection<Target> queue = new BlockingCollection<Target>(n);
            List<Thread> workers = new List<Thread>();
            for (int i = 0; i < n; i++)
            {
                Thread t = new Thread(delegate ()
                {
                    foreach (Target h in queue.GetConsumingEnumerable())
                    {
                        if (stopping) break;
                        try { ScanTLS(h); }
                        catch (Exception e) { Log("DEBUG", "TLS handshake failed", "target", FormatIP(h.Ip ?? new byte[16]), "err", e.Message); }
                    }
                });
                t.IsBackground = true;
                t.Start();
                workers.Add(t);
            }
            foreach (Target h in hosts)
            {
                if (stopping) break;
                while (!queue.TryAdd(h, 200)) if (stopping) break;
                if (stopping) break;
            }
            queue.CompleteAdding();
            foreach (Thread t in workers)
            {
                while (!t.Join(200)) if (stopping) return;
            }
        }
    }

    // ------------------------------------------------------------- TLS client
    // Just enough of TLS 1.2/1.3 to read what Go's crypto/tls would report:
    // version, ALPN, key exchange group and the certificate chain.

    public class TlsResult
    {
        public bool Dialed;
        public bool Ok;
        public int Version;
        public string Alpn = "";
        public int Curve;
        public List<byte[]> Certs = new List<byte[]>();
    }

    public static class Tls
    {
        static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        static readonly byte[] HrrRandom = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

        public static TlsResult Probe(IPAddress address, long port, string sni, long timeoutSec, ConcurrentDictionary<Socket, byte> registry)
        {
            TlsResult r = new TlsResult();
            if (port < 0 || port > 65535) return r;
            long ms = timeoutSec * 1000;
            if (timeoutSec > int.MaxValue / 1000) ms = int.MaxValue;
            Socket s;
            try { s = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp); }
            catch (Exception) { return r; } // e.g. no IPv6 on this machine
            registry[s] = 0;
            try
            {
                try
                {
                    IAsyncResult ar = s.BeginConnect(new IPEndPoint(address, (int)port), null, null);
                    // Go: DialTimeout(0) means no timeout
                    bool done = timeoutSec > 0 ? ar.AsyncWaitHandle.WaitOne((int)ms) : ar.AsyncWaitHandle.WaitOne();
                    if (!done) return r;
                    s.EndConnect(ar);
                }
                catch (Exception) { return r; }
                r.Dialed = true;
                Stopwatch deadline = Stopwatch.StartNew();
                try
                {
                    Handshake(new Conn(s, ms, deadline), sni, r);
                    r.Ok = true;
                }
                catch (Exception) { r.Ok = false; }
                return r;
            }
            finally
            {
                byte dummy;
                registry.TryRemove(s, out dummy);
                try { s.Close(); } catch (Exception) { }
            }
        }

        class Conn
        {
            Socket s; long limit; Stopwatch clock;
            public Conn(Socket sock, long ms, Stopwatch sw) { s = sock; limit = ms; clock = sw; }

            int Remaining()
            {
                long left = limit - clock.ElapsedMilliseconds;
                if (left <= 0) throw new TimeoutException();
                return (int)Math.Min(left, int.MaxValue);
            }

            public void Send(byte[] b)
            {
                int off = 0;
                while (off < b.Length)
                {
                    s.SendTimeout = Remaining();
                    off += s.Send(b, off, b.Length - off, SocketFlags.None);
                }
            }

            public void ReadFull(byte[] b, int off, int n)
            {
                while (n > 0)
                {
                    s.ReceiveTimeout = Remaining();
                    int k = s.Receive(b, off, n, SocketFlags.None);
                    if (k <= 0) throw new EndOfStreamException();
                    off += k; n -= k;
                }
            }

            public byte[] Record(out int type)
            {
                byte[] h = new byte[5];
                ReadFull(h, 0, 5);
                type = h[0];
                int len = (h[3] << 8) | h[4];
                if (len > 18432) throw new InvalidDataException("record too large");
                byte[] f = new byte[len];
                ReadFull(f, 0, len);
                return f;
            }
        }

        class Writer
        {
            public MemoryStream M = new MemoryStream();
            public void U8(int v) { M.WriteByte((byte)v); }
            public void U16(int v) { U8(v >> 8); U8(v); }
            public void U24(int v) { U8(v >> 16); U8(v >> 8); U8(v); }
            public void Bytes(byte[] b) { M.Write(b, 0, b.Length); }
            public byte[] ToArray() { return M.ToArray(); }
        }

        static byte[] Ext(int type, byte[] body)
        {
            Writer w = new Writer();
            w.U16(type); w.U16(body.Length); w.Bytes(body);
            return w.ToArray();
        }

        static byte[] ClientHello(string sni, byte[] pub)
        {
            Writer ext = new Writer();
            if (sni != null)
            {
                byte[] name = Encoding.ASCII.GetBytes(sni);
                Writer b = new Writer();
                b.U16(name.Length + 3); b.U8(0); b.U16(name.Length); b.Bytes(name);
                ext.Bytes(Ext(0x0000, b.ToArray()));
            }
            ext.Bytes(Ext(0x0005, new byte[] { 1, 0, 0, 0, 0 }));      // status_request
            ext.Bytes(Ext(0x000a, new byte[] { 0, 2, 0x00, 0x1d }));   // supported_groups: x25519
            ext.Bytes(Ext(0x000b, new byte[] { 1, 0 }));                // ec_point_formats
            int[] sigs = { 0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203 };
            Writer sa = new Writer();
            sa.U16(sigs.Length * 2);
            foreach (int x in sigs) sa.U16(x);
            ext.Bytes(Ext(0x000d, sa.ToArray()));                       // signature_algorithms
            ext.Bytes(Ext(0xff01, new byte[] { 0 }));                   // renegotiation_info
            Writer alpn = new Writer();
            alpn.U16(12); alpn.U8(2); alpn.Bytes(Encoding.ASCII.GetBytes("h2"));
            alpn.U8(8); alpn.Bytes(Encoding.ASCII.GetBytes("http/1.1"));
            ext.Bytes(Ext(0x0010, alpn.ToArray()));                     // ALPN
            ext.Bytes(Ext(0x0012, new byte[0]));                        // SCT
            ext.Bytes(Ext(0x0017, new byte[0]));                        // extended_master_secret
            ext.Bytes(Ext(0x002b, new byte[] { 4, 3, 4, 3, 3 }));       // supported_versions 1.3, 1.2
            Writer ks = new Writer();
            ks.U16(36); ks.U16(0x001d); ks.U16(32); ks.Bytes(pub);
            ext.Bytes(Ext(0x0033, ks.ToArray()));                       // key_share
            byte[] exts = ext.ToArray();

            byte[] random = new byte[32], session = new byte[32];
            rng.GetBytes(random);
            rng.GetBytes(session);
            int[] suites = { 0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014 };
            Writer body = new Writer();
            body.U16(0x0303); body.Bytes(random);
            body.U8(32); body.Bytes(session);
            body.U16(suites.Length * 2);
            foreach (int x in suites) body.U16(x);
            body.U8(1); body.U8(0);
            body.U16(exts.Length); body.Bytes(exts);
            byte[] b2 = body.ToArray();
            Writer msg = new Writer();
            msg.U8(1); msg.U24(b2.Length); msg.Bytes(b2);
            return msg.ToArray();
        }

        // Handshake messages, read from plaintext or decrypted records.
        class Messages
        {
            MemoryStream buf = new MemoryStream();
            public Func<byte[]> More;

            public byte[] Next(out int type)
            {
                while (true)
                {
                    byte[] b = buf.ToArray();
                    if (b.Length >= 4)
                    {
                        int len = (b[1] << 16) | (b[2] << 8) | b[3];
                        if (b.Length >= 4 + len)
                        {
                            type = b[0];
                            byte[] msg = new byte[4 + len];
                            Array.Copy(b, msg, msg.Length);
                            buf = new MemoryStream();
                            buf.Write(b, msg.Length, b.Length - msg.Length);
                            return msg;
                        }
                    }
                    byte[] more = More();
                    buf.Write(more, 0, more.Length);
                }
            }
        }

        static int U16(byte[] b, int i) { return (b[i] << 8) | b[i + 1]; }
        static int U24(byte[] b, int i) { return (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]; }

        static string ParseAlpn(byte[] b, int off, int len)
        {
            if (len < 3) return "";
            int n = b[off + 2];
            return Encoding.ASCII.GetString(b, off + 3, n);
        }

        static void Handshake(Conn c, string sni, TlsResult r)
        {
            byte[] priv = new byte[32];
            rng.GetBytes(priv);
            byte[] pub = X25519(priv, Base9());
            byte[] ch = ClientHello(sni, pub);
            Writer rec = new Writer();
            rec.U8(22); rec.U16(0x0301); rec.U16(ch.Length); rec.Bytes(ch);
            c.Send(rec.ToArray());

            Messages plain = new Messages();
            plain.More = delegate ()
            {
                while (true)
                {
                    int type;
                    byte[] f = c.Record(out type);
                    if (type == 22) return f;
                    if (type == 21) throw new InvalidDataException("alert");
                    if (type != 20) throw new InvalidDataException("unexpected record");
                }
            };
            int mt;
            byte[] sh = plain.Next(out mt);
            if (mt != 2) throw new InvalidDataException("expected ServerHello");
            int p = 4;
            int legacy = U16(sh, p); p += 2;
            bool hrr = true;
            for (int i = 0; i < 32; i++) if (sh[p + i] != HrrRandom[i]) hrr = false;
            if (hrr) throw new InvalidDataException("HelloRetryRequest");
            p += 32;
            p += 1 + sh[p];
            int suite = U16(sh, p); p += 2;
            p += 1;
            int version = legacy, group = -1;
            byte[] serverKey = null;
            if (p + 2 <= sh.Length)
            {
                int end = p + 2 + U16(sh, p); p += 2;
                while (p + 4 <= end)
                {
                    int et = U16(sh, p), el = U16(sh, p + 2);
                    int eo = p + 4;
                    if (et == 0x002b) version = U16(sh, eo);
                    else if (et == 0x0033) { group = U16(sh, eo); int kl = U16(sh, eo + 2); serverKey = new byte[kl]; Array.Copy(sh, eo + 4, serverKey, 0, kl); }
                    else if (et == 0x0010) r.Alpn = ParseAlpn(sh, eo, el);
                    p = eo + el;
                }
            }
            r.Version = version;
            if (version == 0x0303)
            {
                // TLS 1.2: everything we need is in plaintext
                while (true)
                {
                    byte[] m = plain.Next(out mt);
                    if (mt == 11) ParseCerts12(m, r);
                    else if (mt == 12) { if (m[4] == 3) r.Curve = U16(m, 5); }
                    else if (mt == 14) break;
                }
                return;
            }
            if (version != 0x0304) throw new InvalidDataException("unsupported version");
            if (group != 0x001d || serverKey == null || serverKey.Length != 32) throw new InvalidDataException("bad key share");
            r.Curve = group;

            bool sha384 = suite == 0x1302;
            if (suite != 0x1301 && !sha384) throw new InvalidDataException("unsupported cipher suite");
            int hlen = sha384 ? 48 : 32, klen = sha384 ? 32 : 16;
            byte[] shared = X25519(priv, serverKey);
            byte[] transcript = Hash(sha384, Concat(ch, sh));
            byte[] zeros = new byte[hlen];
            byte[] early = Hmac(sha384, zeros, zeros);
            byte[] derived = ExpandLabel(sha384, early, "derived", Hash(sha384, new byte[0]), hlen);
            byte[] hs = Hmac(sha384, derived, shared);
            byte[] sts = ExpandLabel(sha384, hs, "s hs traffic", transcript, hlen);
            byte[] key = ExpandLabel(sha384, sts, "key", new byte[0], klen);
            byte[] iv = ExpandLabel(sha384, sts, "iv", new byte[0], 12);
            long seq = 0;

            Messages enc = new Messages();
            enc.More = delegate ()
            {
                while (true)
                {
                    int type;
                    byte[] f = c.Record(out type);
                    if (type == 20) continue;
                    if (type == 21) throw new InvalidDataException("alert");
                    if (type != 23 || f.Length < 17) throw new InvalidDataException("unexpected record");
                    byte[] nonce = (byte[])iv.Clone();
                    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (byte)(seq >> (8 * i));
                    seq++;
                    byte[] pt = GcmDecrypt(key, nonce, f, f.Length - 16);
                    int n = pt.Length;
                    while (n > 0 && pt[n - 1] == 0) n--;
                    if (n == 0) throw new InvalidDataException("empty record");
                    int inner = pt[n - 1];
                    if (inner == 21) throw new InvalidDataException("alert");
                    if (inner != 22) continue;
                    byte[] data = new byte[n - 1];
                    Array.Copy(pt, data, n - 1);
                    return data;
                }
            };
            while (true)
            {
                byte[] m = enc.Next(out mt);
                if (mt == 8)
                {
                    int q = 4, end = 4 + 2 + U16(m, 4);
                    q += 2;
                    while (q + 4 <= end)
                    {
                        int et = U16(m, q), el = U16(m, q + 2);
                        if (et == 0x0010) r.Alpn = ParseAlpn(m, q + 4, el);
                        q += 4 + el;
                    }
                }
                else if (mt == 11)
                {
                    int q = 4;
                    q += 1 + m[q];
                    int end = q + 3 + U24(m, q);
                    q += 3;
                    while (q + 3 <= end)
                    {
                        int cl = U24(m, q);
                        byte[] der = new byte[cl];
                        Array.Copy(m, q + 3, der, 0, cl);
                        r.Certs.Add(der);
                        q += 3 + cl;
                        q += 2 + U16(m, q);
                    }
                    return;
                }
            }
        }

        static void ParseCerts12(byte[] m, TlsResult r)
        {
            int q = 4, end = 4 + 3 + U24(m, 4);
            q += 3;
            while (q + 3 <= end)
            {
                int cl = U24(m, q);
                byte[] der = new byte[cl];
                Array.Copy(m, q + 3, der, 0, cl);
                r.Certs.Add(der);
                q += 3 + cl;
            }
        }

        // --- crypto helpers

        static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Array.Copy(a, r, a.Length);
            Array.Copy(b, 0, r, a.Length, b.Length);
            return r;
        }

        static byte[] Hash(bool sha384, byte[] data)
        {
            using (HashAlgorithm h = sha384 ? (HashAlgorithm)SHA384.Create() : SHA256.Create()) return h.ComputeHash(data);
        }

        static byte[] Hmac(bool sha384, byte[] key, byte[] data)
        {
            using (HMAC h = sha384 ? (HMAC)new HMACSHA384(key) : new HMACSHA256(key)) return h.ComputeHash(data);
        }

        static byte[] ExpandLabel(bool sha384, byte[] secret, string label, byte[] context, int length)
        {
            byte[] l = Encoding.ASCII.GetBytes("tls13 " + label);
            Writer info = new Writer();
            info.U16(length); info.U8(l.Length); info.Bytes(l); info.U8(context.Length); info.Bytes(context);
            byte[] inf = info.ToArray();
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int done = 0;
            for (int i = 1; done < length; i++)
            {
                byte[] input = Concat(Concat(t, inf), new byte[] { (byte)i });
                t = Hmac(sha384, secret, input);
                int n = Math.Min(t.Length, length - done);
                Array.Copy(t, 0, okm, done, n);
                done += n;
            }
            return okm;
        }

        // AES-GCM decryption without tag check (CTR mode from counter 2): we only
        // need to read the server's handshake, not to trust it.
        static byte[] GcmDecrypt(byte[] key, byte[] nonce, byte[] data, int len)
        {
            byte[] outp = new byte[len];
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                using (ICryptoTransform e = aes.CreateEncryptor())
                {
                    byte[] ctr = new byte[16], ks = new byte[16];
                    Array.Copy(nonce, ctr, 12);
                    uint counter = 2;
                    for (int off = 0; off < len; off += 16)
                    {
                        ctr[12] = (byte)(counter >> 24); ctr[13] = (byte)(counter >> 16);
                        ctr[14] = (byte)(counter >> 8); ctr[15] = (byte)counter;
                        e.TransformBlock(ctr, 0, 16, ks, 0);
                        for (int i = 0; i < 16 && off + i < len; i++) outp[off + i] = (byte)(data[off + i] ^ ks[i]);
                        counter++;
                    }
                }
            }
            return outp;
        }

        static byte[] Base9()
        {
            byte[] b = new byte[32];
            b[0] = 9;
            return b;
        }

        static BigInteger Mod(BigInteger a)
        {
            BigInteger r = BigInteger.Remainder(a, P);
            return r.Sign < 0 ? r + P : r;
        }

        static BigInteger FromLE(byte[] b)
        {
            byte[] t = new byte[33];
            Array.Copy(b, t, 32);
            return new BigInteger(t);
        }

        // RFC 7748 X25519
        static byte[] X25519(byte[] scalar, byte[] u)
        {
            byte[] k = (byte[])scalar.Clone();
            k[0] &= 248; k[31] &= 127; k[31] |= 64;
            byte[] uu = (byte[])u.Clone();
            uu[31] &= 127;
            BigInteger x1 = Mod(FromLE(uu)), x2 = 1, z2 = 0, x3 = x1, z3 = 1;
            int swap = 0;
            for (int t = 254; t >= 0; t--)
            {
                int kt = (k[t >> 3] >> (t & 7)) & 1;
                swap ^= kt;
                if (swap == 1) { BigInteger tmp = x2; x2 = x3; x3 = tmp; tmp = z2; z2 = z3; z3 = tmp; }
                swap = kt;
                BigInteger a = Mod(x2 + z2), aa = Mod(a * a), b = Mod(x2 - z2), bb = Mod(b * b), e = Mod(aa - bb);
                BigInteger cc = Mod(x3 + z3), d = Mod(x3 - z3), da = Mod(d * a), cb = Mod(cc * b);
                x3 = Mod((da + cb) * (da + cb));
                z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
                x2 = Mod(aa * bb);
                z2 = Mod(e * (aa + 121665 * e));
            }
            if (swap == 1) { x2 = x3; z2 = z3; }
            BigInteger res = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
            byte[] o = res.ToByteArray();
            byte[] r32 = new byte[32];
            Array.Copy(o, r32, Math.Min(32, o.Length));
            return r32;
        }
    }

    // ------------------------------------------------------- X.509 certificates

    public class CertInfo
    {
        public string CommonName = "";
        public List<string> IssuerOrg = new List<string>();
        public bool HasDNS;
        public string Signature = "0";
        public string PublicKey = "0";

        // one DER element: tag, start of the content, content length
        struct Tlv { public int Tag, Start, Len; public int End { get { return Start + Len; } } }

        static Tlv Read(byte[] b, int pos)
        {
            Tlv t = new Tlv();
            t.Tag = b[pos++];
            int len = b[pos++];
            if (len >= 0x80)
            {
                int n = len & 0x7f;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | b[pos++];
            }
            t.Start = pos;
            t.Len = len;
            if (t.End > b.Length) throw new InvalidDataException("bad DER");
            return t;
        }

        static List<Tlv> Children(byte[] b, Tlv parent)
        {
            List<Tlv> list = new List<Tlv>();
            int p = parent.Start;
            while (p < parent.End)
            {
                Tlv t = Read(b, p);
                list.Add(t);
                p = t.End;
            }
            return list;
        }

        static string Oid(byte[] b, Tlv t)
        {
            StringBuilder sb = new StringBuilder();
            long v = 0;
            bool first = true;
            for (int i = t.Start; i < t.End; i++)
            {
                v = (v << 7) | (uint)(b[i] & 0x7f);
                if ((b[i] & 0x80) != 0) continue;
                if (first)
                {
                    long a = v < 80 ? v / 40 : 2;
                    sb.Append(a).Append('.').Append(v - a * 40);
                    first = false;
                }
                else sb.Append('.').Append(v);
                v = 0;
            }
            return sb.ToString();
        }

        static string Str(byte[] b, Tlv t)
        {
            switch (t.Tag)
            {
                case 0x1e: return Encoding.BigEndianUnicode.GetString(b, t.Start, t.Len);
                case 0x1c: return new UTF32Encoding(true, false).GetString(b, t.Start, t.Len);
                case 0x14: return Encoding.GetEncoding(28591).GetString(b, t.Start, t.Len);
                default: return Encoding.UTF8.GetString(b, t.Start, t.Len);
            }
        }

        static void Names(byte[] b, Tlv name, string oid, List<string> outp)
        {
            foreach (Tlv set in Children(b, name))
                foreach (Tlv atv in Children(b, set))
                {
                    List<Tlv> kv = Children(b, atv);
                    if (kv.Count >= 2 && Oid(b, kv[0]) == oid) outp.Add(Str(b, kv[1]));
                }
        }

        static string SigName(byte[] b, Tlv alg)
        {
            List<Tlv> a = Children(b, alg);
            string oid = Oid(b, a[0]);
            switch (oid)
            {
                case "1.2.840.113549.1.1.2": return "MD2-RSA";
                case "1.2.840.113549.1.1.4": return "MD5-RSA";
                case "1.2.840.113549.1.1.5": case "1.3.14.3.2.29": return "SHA1-RSA";
                case "1.2.840.113549.1.1.11": return "SHA256-RSA";
                case "1.2.840.113549.1.1.12": return "SHA384-RSA";
                case "1.2.840.113549.1.1.13": return "SHA512-RSA";
                case "1.2.840.10040.4.3": return "DSA-SHA1";
                case "2.16.840.1.101.3.4.3.2": return "DSA-SHA256";
                case "1.2.840.10045.4.1": return "ECDSA-SHA1";
                case "1.2.840.10045.4.3.2": return "ECDSA-SHA256";
                case "1.2.840.10045.4.3.3": return "ECDSA-SHA384";
                case "1.2.840.10045.4.3.4": return "ECDSA-SHA512";
                case "1.3.101.112": return "Ed25519";
                case "1.2.840.113549.1.1.10":
                    try
                    {
                        // RSASSA-PSS-params: [0] hashAlgorithm
                        foreach (Tlv f in Children(b, a[1]))
                            if (f.Tag == 0xa0)
                            {
                                string h = Oid(b, Children(b, Children(b, f)[0])[0]);
                                if (h == "2.16.840.1.101.3.4.2.1") return "SHA256-RSAPSS";
                                if (h == "2.16.840.1.101.3.4.2.2") return "SHA384-RSAPSS";
                                if (h == "2.16.840.1.101.3.4.2.3") return "SHA512-RSAPSS";
                            }
                    }
                    catch (Exception) { }
                    return "0";
            }
            return "0";
        }

        public static CertInfo Parse(byte[] der)
        {
            CertInfo ci = new CertInfo();
            try
            {
                Tlv cert = Read(der, 0);
                List<Tlv> top = Children(der, cert);
                ci.Signature = SigName(der, top[1]);
                List<Tlv> tbs = Children(der, top[0]);
                int i = 0;
                if (tbs[0].Tag == 0xa0) i++;
                Tlv issuer = tbs[i + 2], subject = tbs[i + 4], spki = tbs[i + 5];
                Names(der, issuer, "2.5.4.10", ci.IssuerOrg);
                List<string> cn = new List<string>();
                Names(der, subject, "2.5.4.3", cn);
                if (cn.Count > 0) ci.CommonName = cn[cn.Count - 1];
                switch (Oid(der, Children(der, Children(der, spki)[0])[0]))
                {
                    case "1.2.840.113549.1.1.1": ci.PublicKey = "RSA"; break;
                    case "1.2.840.10040.4.1": ci.PublicKey = "DSA"; break;
                    case "1.2.840.10045.2.1": ci.PublicKey = "ECDSA"; break;
                    case "1.3.101.112": ci.PublicKey = "Ed25519"; break;
                }
                for (int j = i + 6; j < tbs.Count; j++)
                {
                    if (tbs[j].Tag != 0xa3) continue;
                    foreach (Tlv ext in Children(der, Children(der, tbs[j])[0]))
                    {
                        List<Tlv> e = Children(der, ext);
                        if (Oid(der, e[0]) != "2.5.29.17") continue;
                        Tlv val = e[e.Count - 1];
                        foreach (Tlv gn in Children(der, Read(der, val.Start)))
                            if (gn.Tag == 0x82) ci.HasDNS = true;
                    }
                }
            }
            catch (Exception) { }
            return ci;
        }
    }

    // --------------------------------------------------------- MaxMind GeoIP

    public class Geo
    {
        byte[] buf;
        long nodes, recordSize, ipVersion, treeSize, metaStart;

        public static Geo Open(string path)
        {
            if (!File.Exists(path))
            {
                string why = Environment.OSVersion.Platform == PlatformID.Win32NT
                    ? "The system cannot find the file specified." : "no such file or directory";
                Scanner.Log("WARN", "Cannot open Country.mmdb", "err", "open Country.mmdb: " + why);
                return null;
            }
            Geo g = new Geo();
            try
            {
                g.buf = File.ReadAllBytes(path);
                byte[] marker = { 0xab, 0xcd, 0xef, (byte)'M', (byte)'a', (byte)'x', (byte)'M', (byte)'i', (byte)'n', (byte)'d', (byte)'.', (byte)'c', (byte)'o', (byte)'m' };
                int at = -1;
                for (int i = g.buf.Length - marker.Length; i >= 0 && at < 0; i--)
                {
                    int k = 0;
                    while (k < marker.Length && g.buf[i + k] == marker[k]) k++;
                    if (k == marker.Length) at = i;
                }
                if (at < 0) throw new InvalidDataException("invalid MaxMind DB file");
                g.metaStart = at + marker.Length;
                int end;
                Dictionary<string, object> meta = (Dictionary<string, object>)g.Decode((int)g.metaStart, (int)g.metaStart, out end);
                g.nodes = Convert.ToInt64(meta["node_count"]);
                g.recordSize = Convert.ToInt64(meta["record_size"]);
                g.ipVersion = Convert.ToInt64(meta["ip_version"]);
                g.treeSize = g.recordSize * 2 / 8 * g.nodes;
            }
            catch (Exception)
            {
                Scanner.Log("WARN", "Cannot open Country.mmdb", "err", "error opening database: invalid MaxMind DB file");
                return null;
            }
            Scanner.Log("INFO", "Enabled GeoIP");
            return g;
        }

        long BE(int off, int n)
        {
            long v = 0;
            for (int i = 0; i < n; i++) v = (v << 8) | buf[off + i];
            return v;
        }

        object Decode(int off, int dataBase, out int next)
        {
            int ctrl = buf[off++];
            int type = ctrl >> 5;
            if (type == 1)
            {
                int ss = (ctrl >> 3) & 3, v = ctrl & 7;
                long ptr;
                if (ss == 0) { ptr = (v << 8) | buf[off]; off += 1; }
                else if (ss == 1) { ptr = ((v << 16) | (int)BE(off, 2)) + 2048; off += 2; }
                else if (ss == 2) { ptr = (((long)v << 24) | BE(off, 3)) + 526336; off += 3; }
                else { ptr = BE(off, 4); off += 4; }
                next = off;
                int ignored;
                return Decode((int)(dataBase + ptr), dataBase, out ignored);
            }
            if (type == 0) { type = buf[off] + 7; off++; }
            int size = ctrl & 0x1f;
            if (size == 29) { size = 29 + buf[off]; off += 1; }
            else if (size == 30) { size = 285 + (int)BE(off, 2); off += 2; }
            else if (size == 31) { size = 65821 + (int)BE(off, 3); off += 3; }
            switch (type)
            {
                case 7:
                    {
                        Dictionary<string, object> d = new Dictionary<string, object>();
                        for (int i = 0; i < size; i++)
                        {
                            object k = Decode(off, dataBase, out off);
                            object val = Decode(off, dataBase, out off);
                            d[k as string ?? ""] = val;
                        }
                        next = off;
                        return d;
                    }
                case 11:
                    {
                        List<object> a = new List<object>();
                        for (int i = 0; i < size; i++) a.Add(Decode(off, dataBase, out off));
                        next = off;
                        return a;
                    }
                case 14:
                    next = off;
                    return size != 0;
                case 2:
                    next = off + size;
                    return Encoding.UTF8.GetString(buf, off, size);
                case 5: case 6: case 9: case 10:
                    next = off + size;
                    return size <= 8 ? (object)BE(off, size) : (object)0L;
                default:
                    next = off + size;
                    return null;
            }
        }

        long Record(long node, int bit)
        {
            long o = node * recordSize * 2 / 8;
            if (recordSize == 24) return BE((int)(o + 3 * bit), 3);
            if (recordSize == 28)
            {
                int m = buf[o + 3];
                if (bit == 0) return ((long)(m & 0xf0) << 20) | BE((int)o, 3);
                return ((long)(m & 0x0f) << 24) | BE((int)(o + 4), 3);
            }
            if (recordSize == 32) return BE((int)(o + 4 * bit), 4);
            throw new InvalidDataException("unsupported record size");
        }

        // ISO code, "" when unknown, "N/A" on errors (like the Go version)
        public string Country(byte[] ip)
        {
            try
            {
                bool v4 = true;
                for (int i = 0; i < 10; i++) if (ip[i] != 0) v4 = false;
                if (ip[10] != 0xff || ip[11] != 0xff) v4 = false;
                long node = 0;
                int start = 0;
                if (v4)
                {
                    start = 96;
                    if (ipVersion == 6)
                        for (int i = 0; i < 96 && node < nodes; i++) node = Record(node, 0);
                }
                else if (ipVersion == 4)
                    throw new InvalidDataException("error looking up '" + Scanner.FormatIP(ip) + "': you attempted to look up an IPv6 address in an IPv4-only database");
                for (int i = start; i < 128 && node < nodes; i++)
                    node = Record(node, (ip[i >> 3] >> (7 - (i & 7))) & 1);
                if (node == nodes) return "";
                if (node < nodes) throw new InvalidDataException("invalid node in search tree");
                int next;
                Dictionary<string, object> rec = Decode((int)(treeSize + node - nodes), (int)(treeSize + 16), out next) as Dictionary<string, object>;
                object country;
                if (rec != null && rec.TryGetValue("country", out country))
                {
                    Dictionary<string, object> c = country as Dictionary<string, object>;
                    object iso;
                    if (c != null && c.TryGetValue("iso_code", out iso)) return iso as string ?? "";
                }
                return "";
            }
            catch (Exception e)
            {
                Scanner.Log("DEBUG", "Error reading geo", "err", e.Message);
                return "N/A";
            }
        }
    }
}
'@

if (-not ('RealiTLScannerPS1.Scanner' -as [type])) {
    $addType = @{ TypeDefinition = $source; Language = 'CSharp'; IgnoreWarnings = $true }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 (.NET Framework): BigInteger and Aes live here
        $addType.ReferencedAssemblies = @('System.Numerics', 'System.Core')
    }
    Add-Type @addType -WarningAction SilentlyContinue
}

# Started from Explorer (double click or "Run with PowerShell") rather than
# from a console: there are no arguments to give and the window closes as soon
# as the script ends.
function Test-StartedFromExplorer {
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false }
    try {
        $self = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction Stop
        $parent = Get-Process -Id $self.ParentProcessId -ErrorAction Stop
        return $parent.ProcessName -eq 'explorer'
    } catch {
        return $false
    }
}

$scanArgs = [string[]]@($args | ForEach-Object { "$_" })
$interactive = $scanArgs.Count -eq 0 -and (Test-StartedFromExplorer)
$workDir = (Get-Location).ProviderPath
if ($interactive) {
    # Explorer may start us in another folder: keep the CSV and Country.mmdb next to the script
    if ($PSScriptRoot) { $workDir = $PSScriptRoot }
    Write-Host 'RealiTLScanner' -ForegroundColor Cyan
    Write-Host 'Looks for TLS servers that suit Xray REALITY as "dest", next to the address you give.'
    Write-Host ''
    while ($true) {
        $target = (Read-Host 'Enter an IP, CIDR (e.g. 1.2.3.0/24) or domain to scan').Trim()
        if ($target -eq '') { continue }
        if ([RealiTLScannerPS1.Scanner]::IsValidAddr($target)) { break }
        Write-Host "`"$target`" is not an IP, CIDR or resolvable domain, try again." -ForegroundColor Yellow
    }
    if ($target -notmatch '/') {
        Write-Host 'The scan walks outward from this address until you press Ctrl+C.' -ForegroundColor DarkGray
    }
    Write-Host ''
    $scanArgs = [string[]]@('-addr', $target, '-out', (Join-Path $workDir 'out.csv'))
}

$programName = if ($PSCommandPath) { $PSCommandPath } else { 'RealiTLScanner.ps1' }
try {
    $exitCode = [RealiTLScannerPS1.Scanner]::Run($scanArgs, $programName, $workDir)
} finally {
    if ($interactive) {
        # Console.ReadLine still works while PowerShell is stopping after Ctrl+C
        [Console]::Out.WriteLine()
        [Console]::Out.WriteLine('Press Enter to close this window')
        [void][Console]::ReadLine()
    }
}
exit $exitCode
