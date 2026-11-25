# ProxyTun (App Proxy Manager) for Windows

Route **selected Windows applications** through a local SOCKS5 / HTTP proxy (default: Hiddify at `127.0.0.1:12334`, SOCKS5)
while every other application keeps its normal direct connection. No system proxy is touched, no per-app proxy settings are needed,
no certificates are installed, no HTTPS is intercepted.

> **Verification status — please read.** The development environment for this project was Linux with no Windows machine.
> See [What has and has not been tested](#what-has-and-has-not-been-tested). In short: the proxy client, redirector, UDP relay,
> packet rewriting and all routing decisions are covered by 30 automated tests that pass; the WinDivert driver integration and the
> WPF UI have **not yet been executed on Windows**, and the public-IP check (`scripts\verify-routing.ps1`) still has to be run by you.

## 1. Architecture (and why)

A SOCKS5 client cannot capture traffic of arbitrary programs, so the app intercepts packets per process.

| Approach | Verdict |
|---|---|
| Windows system proxy | Rejected (global, apps may ignore it). |
| DLL injection / Winsock hooking (Proxifier-style) | Rejected: fragile, breaks with anti-cheat / protected & modern apps, needs injection into every process. |
| Own WFP callout driver | Most powerful but requires writing, signing (EV + attestation) and shipping a kernel driver. Not maintainable here. |
| **WinDivert 2.2 (signed driver + user-mode API)** | **Chosen.** Signed driver exists, has a SOCKET layer that reports *which process owns which socket* and a NETWORK layer for rewriting packets. Used by many tools; the only kernel component is the unmodified upstream driver. |

```
 routed app ──SYN (local:cport → dst:dport)──▶ [WinDivert NETWORK layer]
                                                   │ pid of cport known from [WinDivert SOCKET layer events]
                                                   │ pid's exe in the list?  no → re-inject unchanged (direct)
                                                   ▼ yes
              rewritten to (dst:cport → local:redirPort), injected INBOUND
                                                   ▼
                      TcpRedirector (local listener) ── NAT table: (cport,dst) → original dport
                                                   ▼ SOCKS5 CONNECT dst:dport (or HTTP CONNECT)
                                              your proxy (Hiddify)
 replies: (local:redirPort → dst:cport) are rewritten to (dst:dport → local:cport), so the app sees the real server.
```

* **TCP:** every new connection (SYN) of a routed process is reflected to the local redirector, which opens the real tunnel through the proxy.
* **UDP:** reflected to a local relay which uses SOCKS5 *UDP ASSOCIATE* (one association per client socket). HTTP proxies cannot carry UDP, so non-DNS UDP of routed apps is **dropped** (apps such as browsers fall back from QUIC to TCP) rather than leaked.
* **DNS:** UDP/53 of routed apps is converted to DNS-over-TCP through the proxy to the configured resolver (default `1.1.1.1`) – works with both proxy types and never uses the local/ISP resolver, even if the app asked the router (`192.168.x.1`).
* **IPv6:** TCP/UDP over IPv6 of routed apps is dropped (setting, on by default) so apps fall back to IPv4, which can be proxied. No IPv6 leak.
* **Loop prevention:** the connection to the proxy is made by this program (never routed); loopback destinations are never touched; the program that *provides* the proxy (found via the proxy's listening port) and this program are excluded even if added to the list.
* **Fail closed:** if the proxy is down, routed apps lose connectivity instead of silently going direct. Recovery is automatic when the proxy returns.
* **Unrelated traffic:** packets of every other process are re-injected byte-for-byte unchanged.
* **Matching:** by full executable path, so all instances and all later launches are covered. Already-running apps are covered for **new** connections.

### Known limitations (honest list)

1. **Connections that were already open** when routing started stay direct until they reconnect (enable *Reset already-open connections* in Settings to force it).
2. **Child processes** are matched by their own exe path. Apps that spawn *other* executables for networking (some launchers, updaters) need those exes added too.
3. **DNS through the Windows resolver.** Most apps call `getaddrinfo`, and Windows performs the lookup in the *DNS Client service*, not in the app, so a per-process method cannot attribute it. Their **traffic** is proxied, but the **name lookup** can reach your ISP resolver. Fix: Settings → *Send all system DNS lookups through the proxy* (opt-in; affects how *all* apps resolve names, not their connections). Apps with their own resolver or DoH (Chrome secure DNS, Firefox, Go, Tor…) are fully covered by default.
4. All outbound TCP/UDP passes through a user-mode loop (non-matching packets are re-injected). Expect a small CPU cost on very fast links.
5. UDP relay: one remote port per (client socket, remote IP) is tracked for reply mapping; a socket talking to the *same IP on several ports at once* may get replies attributed to the latest port.
6. IPv4 only for proxied traffic; fragments and ICMP are passed through untouched.
7. WinDivert needs a signed driver to load: Secure Boot is fine, but *Smart App Control*, *Memory Integrity (HVCI)* or the vulnerable-driver blocklist can refuse it (see Troubleshooting).

## 2. Requirements

Windows 10 / 11 x64. To build: .NET SDK 8 or newer. Running a published build needs nothing else. Administrator rights are requested **only when you press Start Routing** (the app otherwise runs as a normal user).

## 3. Build, test, publish

```
build.bat      REM verifies WinDivert SHA-256, builds Release, runs the automated tests
publish.bat    REM standalone win-x64 build -> dist\AppProxyManager\ and dist\AppProxyManager-win-x64.zip
```

Tests only (works on any OS with .NET 8, no packages needed): `dotnet run --project tests/AppProxyManager.Tests`

## 4. Use

1. Start Hiddify (SOCKS5/mixed inbound on `127.0.0.1:12334`). In Hiddify's settings keep "set as system proxy" however you like – it is irrelevant to this app.
2. Open **AppProxyManager.exe**, check host/port/type (credentials optional), press **Test connection** – it shows the proxy's exit IP.
3. **Add Application** (or drag `.exe` files onto the window). Duplicates are rejected. Everything is saved automatically.
4. **Start Routing** → accept the UAC prompt (the app restarts elevated and starts routing). Status per app is shown in the list.
5. **Stop Routing** returns everything to direct instantly. Closing the window hides the app in the system tray and routing continues; choose **Exit** from the tray icon's right-click menu to quit completely (routing then stops).

Settings: launch at sign-in (scheduled task, highest privileges, no UAC prompt at logon), start minimized, auto-start routing, LAN bypass, IPv6 blocking, reset existing connections, system DNS option, DNS server.
Passwords are stored encrypted with Windows DPAPI (current user only). Data: `%APPDATA%\AppProxyManager\config.json`, logs: `%LOCALAPPDATA%\AppProxyManager\logs\app.log`.

## 5. Driver installation and removal

* **Installation is automatic and on demand.** Pressing *Start Routing* opens WinDivert, which loads the bundled, upstream-signed `WinDivert64.sys` as a kernel service named `WinDivert`. Nothing is installed at setup time and nothing runs while routing is stopped.
* On first start the app also adds one Windows Firewall inbound rule for its own exe ("App Proxy Manager (local redirector)"), needed because reflected packets arrive at the local redirector as inbound connections.
* **Removal**
  * Stopping routing closes the driver handles; Windows unloads the service.
  * `scripts\driver-status.bat` – shows the service state.
  * `scripts\uninstall-driver.bat` – stops and deletes the `WinDivert` service immediately.
  * `scripts\uninstall.bat` – full cleanup: driver, firewall rule, sign-in task, optional settings/log deletion. Then delete the program folder.
* Binaries: WinDivert 2.2.2-A x64 from the official release, SHA-256 pinned in `scripts\fetch-windivert.ps1` (`WinDivert.dll` `c1e060ee…d9a2`, `WinDivert64.sys` `8da08533…ddc2`). WinDivert is © basil00, LGPL-3.0 / GPL-2.0 (`third_party\WinDivert\LICENSE`), dynamically linked and unmodified.

## 6. Verify that it really works (public IP check)

```
powershell -File scripts\verify-routing.ps1 -Phase Baseline   (routing stopped)
  → add %TEMP%\apm-verify\curl-proxied.exe in the app and Start Routing
powershell -File scripts\verify-routing.ps1 -Phase Verify
```
`curl.exe` (not listed) must still print your real IP; the identical copy `curl-proxied.exe` (listed) must print the proxy's exit IP. Script prints PASS/FAIL.

## 7. What has and has not been tested

| Area | Status |
|---|---|
| Config store (persistence, DPAPI-style protector interface, corrupt-file recovery, duplicates) | ✅ automated, passing |
| SOCKS5 client (no-auth, user/pass, domain & IPv4 targets, errors) and HTTP CONNECT (+Basic auth) against real in-process proxy servers | ✅ automated, passing |
| Proxy test button logic (exit-IP parsing incl. chunked, dead proxy, wrong proxy type, missing credentials, no hangs) | ✅ automated, passing |
| IPv4 packet parse/rewrite and TCP/UDP/IP checksums (independent verifier, odd lengths) | ✅ automated, passing |
| Routing decisions (`PacketTranslator`): listed vs unlisted, loopback/LAN bypass, loop guard, stale entries, IPv6 drop, UDP, DNS, HTTP-proxy UDP drop, system-DNS opt-in, reply restoration | ✅ automated, passing |
| TCP redirector: 300 KB intact round trip via proxy to original destination, unknown flows dropped, **fail-closed when proxy down** | ✅ automated, passing |
| UDP relay via SOCKS5 UDP ASSOCIATE (association reuse, reply path) and DNS-over-TCP through the proxy | ✅ automated, passing *(this validates the relay logic, **not** the packet path through the driver)* |
| WinDivert driver integration (`RoutingEngine`, P/Invoke structs, socket-layer pid mapping, re-injection) | ⚠️ compiles, **not executed** (no Windows host available). Struct layout follows WinDivert 2.2 headers. |
| WPF UI, DPAPI wrapper, scheduled task, firewall rule, elevation restart | ⚠️ written, **not compiled or run** here (WPF targeting pack unavailable offline). XAML validated as well-formed XML; the non-UI controller compiles. |
| Public IP changes for proxied app / unchanged for direct app | ❌ **not performed** – run `scripts\verify-routing.ps1` |
| **UDP support through the driver** | ❌ **Do not rely on it until you have tested it** (e.g. a QUIC site in a routed browser, or a UDP echo). TCP and DNS are the primary paths. |

If anything fails on first run, the log file and the Troubleshooting section below are the starting point; please send me the log and I'll fix it.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Windows blocked the WinDivert driver (1275)" / "signature (577)" | Turn off *Smart App Control* or *Memory Integrity* (Windows Security → Device security → Core isolation), or update Windows. Corporate policy (WDAC) may forbid the driver. |
| "Access denied (5)" | Not elevated. Use *Start Routing* and accept UAC, or run as Administrator. |
| "Base Filtering Engine not running (1753)" | Start the *Base Filtering Engine* service (`services.msc`). Required by WinDivert. |
| Error 1058/1060/1393 | Stale driver service: run `scripts\uninstall-driver.bat`, retry. |
| Status "Blocked: proxy unreachable" | Hiddify not running / wrong port / wrong type. Use *Test connection*. Apps are blocked on purpose rather than leaking. |
| Test says "Is this an HTTP proxy?" | Port is an HTTP inbound; switch type to HTTP (note: HTTP proxies carry no UDP). |
| Proxied app shows "waiting for traffic" | It has not opened a *new* connection yet, or uses a different helper exe. Restart the app / enable *Reset already-open connections*; add child exes if needed. |
| Website shows wrong region although IP is right | DNS lookups via the Windows resolver, see Limitation 3; enable system DNS option. |
| Browser slow/odd with QUIC | QUIC (UDP) needs a proxy that supports UDP ASSOCIATE; otherwise the browser falls back to TCP after a delay. |
| Nothing is proxied but no error | Check the log; make sure the listed path is the *actual* process (e.g. `chrome.exe`, not a launcher); `scripts\verify-routing.ps1` isolates the cause. |
| Antivirus flags WinDivert | WinDivert is a packet-filter driver and is commonly flagged by heuristics; verify the SHA-256 hashes above. |
| Start fails right after a Windows update | Reboot once; stale WinDivert driver versions are replaced on next load. |

## 9. Security notes

No traffic is stored or sent anywhere except to *your* configured proxy and (for *Test connection*) to `api.ipify.org` / `icanhazip.com` through it. Credentials are DPAPI-encrypted. The local redirector listens on all interfaces but accepts only connections that match a NAT entry created by the packet engine; anything else is closed immediately.

## 10. Layout

```
src/AppProxyManager.Core    proxy clients, NAT, redirector, UDP relay, packet translator, config (portable, fully unit-tested)
src/AppProxyManager.Engine  WinDivert P/Invoke, routing engine, DPAPI, firewall/task helpers (Windows only)
src/AppProxyManager.UI      WPF dark UI
tests/AppProxyManager.Tests dependency-free test runner (dotnet run)
scripts/                    driver/uninstall helpers, WinDivert hash check, public-IP verification
third_party/WinDivert       pinned WinDivert 2.2.2-A x64 binaries + license
```

---

# توضیحات فارسی

## معرفی

**ProxyTun** یا **App Proxy Manager** یک برنامه‌ی Windows برای هدایت ترافیک تعدادی از برنامه‌های انتخاب‌شده از یک پراکسی محلی است. برنامه از پراکسی‌های `SOCKS5` و `HTTP CONNECT` پشتیبانی می‌کند. برنامه‌هایی که در فهرست قرار نگرفته‌اند، بدون تغییر و به‌صورت مستقیم به اینترنت متصل می‌شوند.

ProxyTun از Windows System Proxy استفاده نمی‌کند، به تنظیم جداگانه داخل هر برنامه نیاز ندارد، گواهی نصب نمی‌کند و ترافیک HTTPS را رمزگشایی یا مشاهده نمی‌کند. این پروژه به سرویس خاصی مثل Hiddify یا Proxyfyre وابسته نیست؛ هر پراکسی سازگار را می‌توان با وارد کردن host، port و type در تنظیمات استفاده کرد.

برای دانلود نسخه‌ی آماده‌ی Windows x64 به [آخرین Release](https://github.com/Tiredb0y/proxytun/releases/latest) بروید. فایل Release به‌صورت self-contained منتشر شده و برای اجرا به نصب جداگانه‌ی .NET نیاز ندارد.

> **وضعیت تست:** تست‌های خودکار بخش‌های اصلی شبکه، کلاینت پراکسی، NAT، redirector، UDP relay، بازنویسی packet و تصمیم‌های routing را پوشش می‌دهند. با این حال، اجرای واقعی WinDivert، رابط WPF و بررسی تغییر IP عمومی باید روی یک سیستم Windows انجام شود.

## ۱. معماری برنامه

یک کلاینت SOCKS5 به‌تنهایی نمی‌تواند ترافیک همه‌ی برنامه‌ها را بگیرد. ProxyTun با استفاده از WinDivert ترافیک را در سطح packet بررسی می‌کند و با تشخیص process، فقط packetهای برنامه‌های انتخاب‌شده را به redirector محلی می‌فرستد.

روند کلی برای TCP به این شکل است:

```text
برنامه‌ی انتخاب‌شده
        │
        ▼
WinDivert و تشخیص process/socket
        │
        ▼
redirector محلی و جدول NAT
        │
        ▼
اتصال SOCKS5 CONNECT یا HTTP CONNECT به پراکسی
        │
        ▼
سرور مقصد از مسیر پراکسی
```

- **TCP:** اتصال جدید برنامه‌ی انتخاب‌شده به redirector محلی منتقل می‌شود و redirector آن را از طریق پراکسی باز می‌کند.
- **UDP:** در صورت استفاده از SOCKS5، relay محلی از `UDP ASSOCIATE` استفاده می‌کند. پراکسی‌های HTTP معمولاً UDP را پشتیبانی نمی‌کنند؛ در این حالت UDP غیر DNS برای جلوگیری از نشت حذف می‌شود.
- **DNS:** درخواست UDP روی پورت ۵۳ برنامه‌های انتخاب‌شده به DNS-over-TCP از مسیر پراکسی تبدیل می‌شود. سرور پیش‌فرض `1.1.1.1` است و قابل تغییر است.
- **IPv6:** به‌صورت پیش‌فرض TCP و UDP روی IPv6 برای برنامه‌های route‌شده حذف می‌شود تا برنامه به IPv4 برگردد و نشت IPv6 اتفاق نیفتد.
- **جلوگیری از loop:** اتصال خود برنامه به پراکسی route نمی‌شود. loopback دست‌نخورده می‌ماند و خود ProxyTun و برنامه‌ای که پراکسی را ارائه می‌دهد از routing خارج هستند.
- **Fail closed:** اگر پراکسی قطع باشد، برنامه‌ی انتخاب‌شده اتصال مستقیم پیدا نمی‌کند و ارتباطش مسدود می‌شود. بعد از برگشت پراکسی، recovery به‌صورت خودکار انجام می‌شود.
- **ترافیک سایر برنامه‌ها:** packetهای برنامه‌های انتخاب‌نشده بدون تغییر دوباره inject می‌شوند.
- **تشخیص برنامه:** معیار، مسیر کامل فایل اجرایی است؛ بنابراین همه‌ی instanceهای همان exe و اجراهای بعدی پوشش داده می‌شوند.

### محدودیت‌های مهم

1. اتصال‌هایی که قبل از شروع routing باز بوده‌اند، تا زمان reconnect ممکن است مستقیم باقی بمانند. گزینه‌ی **Reset already-open connections** برای بستن آن‌ها وجود دارد.
2. processهای فرزند بر اساس exe خودشان بررسی می‌شوند. اگر یک launcher یا updater برنامه‌ی دیگری را برای شبکه اجرا کند، آن exe هم باید جداگانه اضافه شود.
3. بیشتر برنامه‌ها DNS را از طریق Windows DNS Client انجام می‌دهند، نه مستقیماً از process خودشان. در نتیجه ممکن است خود lookup به DNS سرویس‌دهنده‌ی اینترنت برسد، هرچند ترافیک بعدی برنامه از پراکسی عبور کند. گزینه‌ی **Send all system DNS lookups through the proxy** برای این حالت وجود دارد و روی DNS همه‌ی برنامه‌ها اثر می‌گذارد.
4. تمام TCP و UDP خروجی از یک حلقه‌ی user-mode عبور می‌کند و روی لینک‌های بسیار سریع کمی مصرف CPU اضافه ایجاد می‌شود.
5. relay مربوط به UDP برای یک socket و یک IP مقصد، mapping پورت را نگه می‌دارد؛ استفاده‌ی هم‌زمان از چند پورت روی یک IP ممکن است mapping پاسخ‌ها را تغییر دهد.
6. ترافیک proxied فقط IPv4 است. fragmentها و ICMP بدون تغییر عبور می‌کنند.
7. برای اجرای WinDivert، درایور signed لازم است. Secure Boot معمولاً مشکلی ایجاد نمی‌کند، اما Smart App Control، Memory Integrity/HVCI یا vulnerable-driver blocklist ممکن است درایور را مسدود کنند.

## ۲. نیازمندی‌ها

- Windows 10 یا Windows 11 نسخه‌ی x64
- برای build کردن: .NET SDK نسخه‌ی ۸ یا جدیدتر
- برای اجرای build منتشرشده: نیاز به نصب جداگانه‌ی .NET نیست
- دسترسی Administrator فقط هنگام فشردن **Start Routing** درخواست می‌شود؛ اجرای عادی برنامه با کاربر معمولی انجام می‌شود.

## ۳. ساخت، تست و انتشار

در پوشه‌ی اصلی پروژه روی Windows اجرا کنید:

```bat
build.bat
```

این script وجود و hash فایل‌های WinDivert را بررسی می‌کند، build نسخه‌ی Release را انجام می‌دهد و تست‌های خودکار را اجرا می‌کند.

برای ساخت نسخه‌ی قابل اجرا و self-contained:

```bat
publish.bat
```

خروجی در `dist\AppProxyManager\` و فایل فشرده در `dist\AppProxyManager-win-x64.zip` ساخته می‌شود.

برای اجرای فقط تست‌ها:

```bat
dotnet run --project tests/AppProxyManager.Tests
```

تست‌ها به package خارجی نیاز ندارند و با .NET 8 روی سیستم‌های دیگر هم قابل اجرا هستند.

## ۴. روش استفاده

1. Hiddify یا هر پراکسی سازگار را اجرا کنید. برای Hiddify، ورودی SOCKS5 یا mixed معمولاً روی `127.0.0.1:12334` قرار دارد. فعال یا غیرفعال بودن System Proxy در Hiddify برای ProxyTun اهمیتی ندارد.
2. فایل `AppProxyManager.exe` را اجرا کنید و host، port و type پراکسی را بررسی کنید. با **Test connection** می‌توانید IP خروجی پراکسی را ببینید.
3. با **Add Application** یک exe اضافه کنید یا فایل‌های exe را روی پنجره بکشید. موارد تکراری پذیرفته نمی‌شوند و تنظیمات به‌صورت خودکار ذخیره می‌شوند.
4. روی **Start Routing** بزنید و درخواست UAC را تأیید کنید. برنامه با دسترسی elevated دوباره اجرا می‌شود و وضعیت هر برنامه را نشان می‌دهد.
5. **Stop Routing** تمام ترافیک را به حالت مستقیم برمی‌گرداند.

بستن پنجره‌ی اصلی برنامه را terminate نمی‌کند؛ برنامه در system tray می‌ماند و routing ادامه پیدا می‌کند. برای خروج کامل، روی آیکن tray راست‌کلیک کرده و **Exit** را انتخاب کنید. خروج کامل یا Stop Routing باعث توقف routing می‌شود.

تنظیمات دیگر شامل اجرای خودکار هنگام ورود به Windows، اجرای minimized، شروع خودکار routing، bypass شبکه‌ی LAN، مسدودسازی IPv6، reset اتصال‌های قبلی، انتقال DNS سیستم از proxy و انتخاب DNS server است. رمزهای عبور با Windows DPAPI برای کاربر فعلی رمزگذاری می‌شوند.

مسیر داده‌ها:

- تنظیمات: `%APPDATA%\AppProxyManager\config.json`
- logها: `%LOCALAPPDATA%\AppProxyManager\logs\app.log`

## ۵. نصب و حذف درایور

نصب درایور به‌صورت خودکار و فقط هنگام نیاز انجام می‌شود. با فشردن **Start Routing**، برنامه درایور signed و همراه `WinDivert64.sys` را با نام سرویس `WinDivert` load می‌کند. هنگام توقف routing، handleهای درایور بسته و سرویس unload می‌شود.

در اولین اجرا، برنامه یک قانون inbound در Windows Firewall برای exe خودش ایجاد می‌کند تا packetهای reflected به redirector محلی برسند.

ابزارهای مدیریت درایور:

- `scripts\driver-status.bat`: نمایش وضعیت سرویس
- `scripts\uninstall-driver.bat`: توقف و حذف فوری سرویس `WinDivert`
- `scripts\uninstall.bat`: پاک‌سازی کامل درایور، firewall rule، scheduled task و در صورت انتخاب تنظیمات و logها

WinDivert نسخه‌ی 2.2.2-A x64 از release رسمی است و hash آن در `scripts\fetch-windivert.ps1` ثابت شده است. فایل‌های WinDivert بدون تغییر و به‌صورت dynamic linked استفاده می‌شوند. مجوز آن LGPL-3.0 / GPL-2.0 است و license در `third_party\WinDivert\LICENSE` قرار دارد.

## ۶. بررسی واقعی routing

برای بررسی IP عمومی، ابتدا baseline را با routing خاموش اجرا کنید:

```powershell
powershell -File scripts/verify-routing.ps1 -Phase Baseline
```

سپس یک کپی از `curl.exe` را در `%TEMP%\apm-verify\curl-proxied.exe` قرار دهید، آن را در برنامه اضافه کنید و routing را شروع کنید. بعد اجرا کنید:

```powershell
powershell -File scripts/verify-routing.ps1 -Phase Verify
```

`curl.exe` که در فهرست نیست باید IP واقعی شما را نشان دهد و `curl-proxied.exe` که در فهرست است باید IP خروجی پراکسی را نشان دهد. script نتیجه‌ی PASS یا FAIL چاپ می‌کند.

## ۷. وضعیت تست‌ها

- Config store، ذخیره‌سازی، recovery فایل خراب و تشخیص موارد تکراری: تست خودکار موفق
- کلاینت SOCKS5 بدون رمز و با username/password و کلاینت HTTP CONNECT: تست خودکار موفق
- منطق Test connection، parsing خروجی IP، proxy خراب، type اشتباه و timeout: تست خودکار موفق
- parsing و بازنویسی packetهای IPv4 و checksumهای TCP/UDP/IP: تست خودکار موفق
- تصمیم‌های routing برای برنامه‌های listed و unlisted، loopback، LAN bypass، loop guard، IPv6، UDP و DNS: تست خودکار موفق
- TCP redirector و round-trip داده‌ی ۳۰۰ کیلوبایتی و fail-closed هنگام قطع پراکسی: تست خودکار موفق
- UDP relay با SOCKS5 UDP ASSOCIATE و DNS-over-TCP: تست خودکار موفق؛ این تست مسیر واقعی packet از درایور را بررسی نمی‌کند
- integration واقعی WinDivert شامل P/Invoke، mapping process و reinjection: روی Windows اجرا نشده است
- رابط WPF، DPAPI wrapper، scheduled task، firewall و restart با elevation: روی Windows اجرا نشده است
- تغییر IP عمومی برای برنامه‌ی proxied و ثابت ماندن IP برنامه‌ی مستقیم: باید با script بالا بررسی شود
- UDP از مسیر واقعی driver: تا زمان تست با یک سایت QUIC یا UDP echo نباید قطعی فرض شود؛ مسیرهای اصلی TCP و DNS هستند

اگر در اجرای اول خطایی دیدید، فایل log و بخش Troubleshooting را بررسی کنید.

## ۸. رفع خطاهای رایج

| خطا یا وضعیت | راه‌حل |
|---|---|
| خطای WinDivert با کد 1275 یا 577 | Smart App Control یا Memory Integrity/HVCI را بررسی کنید و Windows را به‌روز کنید. سیاست سازمانی WDAC هم ممکن است driver را مسدود کند. |
| خطای Access denied (5) | روی **Start Routing** بزنید و UAC را تأیید کنید یا برنامه را با Administrator اجرا کنید. |
| Base Filtering Engine با کد 1753 اجرا نیست | سرویس Base Filtering Engine را در `services.msc` اجرا کنید. |
| خطای 1058، 1060 یا 1393 | سرویس قدیمی است؛ `scripts\uninstall-driver.bat` را اجرا و دوباره امتحان کنید. |
| وضعیت Blocked: proxy unreachable | پراکسی اجرا نیست یا host، port یا type اشتباه است. با **Test connection** بررسی کنید. این مسدودسازی برای جلوگیری از leak عمدی است. |
| پیام Is this an HTTP proxy? | نوع ورودی HTTP است؛ type را روی HTTP بگذارید. HTTP معمولاً UDP را پشتیبانی نمی‌کند. |
| برنامه روی waiting for traffic می‌ماند | هنوز اتصال جدیدی باز نکرده یا از helper exe دیگری استفاده می‌کند. برنامه را restart کنید، reset اتصال‌های قبلی را فعال کنید یا exe فرزند را اضافه کنید. |
| region سایت با IP هماهنگ نیست | DNS ممکن است از Windows resolver عبور کند؛ گزینه‌ی system DNS را فعال کنید. |
| مرورگر با QUIC کند یا ناپایدار است | QUIC به SOCKS5 با UDP ASSOCIATE نیاز دارد؛ در غیر این صورت مرورگر بعد از مدتی به TCP برمی‌گردد. |
| هیچ ترافیکی proxied نمی‌شود | log را بررسی کنید و مطمئن شوید مسیر واقعی process را اضافه کرده‌اید، نه launcher را. script بررسی routing برای جدا کردن علت استفاده می‌شود. |
| آنتی‌ویروس WinDivert را flag می‌کند | WinDivert یک packet-filter driver است و ممکن است با heuristic شناسایی شود؛ hashهای فایل را بررسی کنید. |
| بعد از Windows Update اجرا متوقف شده | یک بار reboot کنید؛ درایور قدیمی ممکن است در load بعدی جایگزین شود. |

## ۹. نکات امنیتی

هیچ ترافیکی در برنامه ذخیره نمی‌شود و ترافیک فقط به پراکسی تنظیم‌شده‌ی شما و برای **Test connection** به `api.ipify.org` یا `icanhazip.com` از مسیر همان پراکسی ارسال می‌شود. رمزهای عبور با DPAPI رمزگذاری می‌شوند.

redirector محلی روی interfaceهای سیستم گوش می‌دهد، اما فقط اتصال‌هایی را قبول می‌کند که در جدول NAT توسط packet engine ثبت شده باشند؛ اتصال‌های دیگر بلافاصله بسته می‌شوند.

## ۱۰. ساختار پروژه

```text
src/AppProxyManager.Core    کلاینت‌های proxy، NAT، redirector، UDP relay، packet translator و config
src/AppProxyManager.Engine  P/Invoke مربوط به WinDivert، routing engine، DPAPI، firewall و taskهای Windows
src/AppProxyManager.UI      رابط کاربری WPF
tests/AppProxyManager.Tests dependency-free test runner (dotnet run)
scripts/                    ابزارهای driver، uninstall، بررسی hash و بررسی IP عمومی
third_party/WinDivert       فایل‌های WinDivert 2.2.2-A x64 و license
```

