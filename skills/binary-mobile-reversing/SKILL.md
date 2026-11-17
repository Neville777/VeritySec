---
name: binary-mobile-reversing
description: >-
  APK/EXE/binaries: UniApp/DCloud/Flutter reverse engineering, certificate pinning bypass, exported components, memory-corruption exploit chains, IoT firmware. Use when reversing APK/EXE, UniApp/Flutter, native .so, or memory-corruption exploits.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## APK / EXE / Binary Reverse Engineering

```
=== APK/EXE/binaries ===
APK: apktool d / jadx | Manifest: check exported components / deeplinks / debuggable | rg for hardcoded keys + API addresses | .so: strings / Ghidra | dynamic: frida / objection
🚨 UniApp/DCloud APK reverse engineering (hybrid H5 app, business logic entirely in JS, not in DEX):
  Identification: __UNI__XXXXXXX + assets/apps/ + uni-jsframework.js (NOT Flutter, no libapp.so) | manifest.json contains a "uni-app" field
  Core file: assets/apps/__UNI__XXX/www/app-service.js (800KB+ obfuscated JS = all business logic) | jadx only shows the shell (native plugin registration); the real logic is in JS
  JS deobfuscation (RC4 + string-array rotation): extract the large a0G() array (10000+ elements) + the a0m(idx,key) decode function (base64 → RC4) + the rotation IIFE → assemble executable JS → batch-decode with node → JSON dictionary (offset → plaintext)
    🔴 Trap: the rotation IIFE may end with a comma (not a semicolon! it belongs to a larger expression) → node reports "Unexpected token" → extract up to the actual terminator
  Encrypted configuration zlsioh.dat / dcloud3.dat: header (96-byte offset table: off40 = block1 decompressed / 44 = compressed / 60 = block2 offset / 64 = block2 size / 80 = block3 offset) + block1 (zlib → DEX) + block2 (encrypted, contains the API domain list ← key, requires .so decryption) + block3 (zlib → AndroidX class mapping)
    zlib magic 78DA = unencrypted, decompress directly | no magic = encrypted block (key in the .so .rodata / immediate values in assembly)
  .so string deobfuscation: extract even-position characters → reverse (e.g. "mAojcl.dubdFiHaebP.nwywfwb" → "www.baidu.com") | strings -n8 lib*.so and look for long strings containing dots
  ⚠️ Traps: x-separated IP strings in the .so (e.g. "x111.230.69.120x118.126.105.164") = DCloud HTTPDNS nodes (NOT the API backend! 140.205.11.x = Alibaba Cloud DNS; 111.230 / 118.126 / 106.52 / 42.193 = Tencent Cloud) | resources.arsc errors are deliberate decompilation protection (does not affect jadx) | fake PNG assets (1-8px) are integrity checks, not data | fcapp.run is only an APK download proxy
  Key API variables: $apiHost / $opHost (set dynamically at runtime, not hardcoded) / urlList / checkAvailableDomainList (HEAD domain/favicon.ico to test connectivity; 200-399 = available)
  High-value endpoints: /app_init / /user/gustRegister (guest registration without verification) / /user/getOssSts (temporary OSS credentials!) / /uploadFile2
  Configuration: manifest.json (appId / version / nativePlugins → wrs-httpserver = embedded HTTP server!) | supplierconfig.json (vivo / xiaomi / huawei / oppo appids) | dcloud_uniplugins.json (plugin manifest)
  ChengZi SDK (site builder): the init3 endpoint returns JSON encrypted with single-byte XOR (key=0x96) → decrypt to get the real APK download link (fu field) + channel code
  Domain fallback: when $apiHost cannot be obtained statically → Android emulator (Waydroid / AVD) + tcpdump / mitmproxy to capture runtime DNS
  See: scripts/js_rc4_deobfuscate.js
🚨 Fast Flutter APK reverse engineering (no unpacking needed): hardening (MogoSec / Bangcle / 360) protects the DEX layer, but Flutter's lib/arm64-v8a/libapp.so (Dart AOT) is usually not encrypted
  strings -n8 libapp.so | grep 'https\?://' → all hardcoded URLs / API domains / S3 addresses / CDNs
  strings -n8 libapp.so | grep -E '^/' → API path matrix (/Member/Login, /Web/VideoList, /BBS/GetSTSToken, etc.)
  strings -n8 libapp.so | grep -iE 'key|secret|token|aws|bucket' → credential / key leaks
  assets/config_*.xml + assets/data_*.dat → encrypted configuration (may contain domains / API addresses) | .DS_Store → macOS developer information leak | assets/xinstall* → channel-tracking SDK
🚨 Native .so string deobfuscation (general pattern): obfuscated strings live in the .rodata section
  Common patterns: even-position character extraction + reversal (e.g. "mAojcl.dubdFiHaebP..." → take even positions → reverse = plaintext domain) | XOR constants | RC4 + base64
  Identification: strings -n8 lib*.so to find 16-byte equal-length strings (AES key/IV) / strings containing dots (domains) / x-separated IP strings (HTTPDNS) | nm --dynamic to find obfuscated exported symbols (16-character random mixed-case)
  Verification: match known strings ("classes.dex" / "io.dcloud.application") against their obfuscated versions → reverse-engineer the algorithm → batch-decode
🚨 General mobile (regular apps that are not UniApp/Flutter):
  Certificate pinning bypass (to capture HTTPS): objection android sslpinning disable | frida universal-unpinning | edit smali to remove pinning and repackage
  Exported component privilege escalation: Activity/Service/Provider/Receiver with exported=true in the Manifest → cross-app invocation via drozer / adb am start | ContentProvider SQLi / path traversal
  Deeplink hijacking: scheme:// without validation → WebView loads arbitrary URLs (XSS / file read) | parameters passed into intents → component hijacking
  Insecure storage: /data/data/pkg/ (plaintext token in shared_prefs / unencrypted db / logcat leaks) | sdcard world-readable
  WebView: addJavascriptInterface (RCE on <4.2) / file:// reads of local files / setAllowFileAccess | static: MobSF one-shot | iOS: decrypt the app (frida-ios-dump) + Ghidra for Mach-O + objection for dynamic analysis
EXE/PE: file / strings | decompile with Ghidra/IDA to find hardcoded values / encryption / network logic | x64dbg dynamic debugging | vulnerabilities: overflow / format string / UAF / DLL hijacking
🚨 Memory-corruption exploit chain (crash → RCE): checksec to check protections → identify the primitive (stack overflow / UAF / format string = arbitrary read/write)
  → info leak to bypass ASLR → ROP chain (ROPgadget / pwntools ret2libc) → heap exploitation (tcache poisoning / __free_hook hijacking)
  → arbitrary write to overwrite GOT / hooks / vtable / exit_funcs → control-flow hijack | IoT firmware: binwalk -Me to extract + qemu-user for debugging (weak protections often mean a direct stack overflow)
```
