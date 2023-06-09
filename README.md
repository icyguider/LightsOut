# LightsOut
LightsOut will generate an obfuscated DLL that will disable AMSI &amp; ETW while trying to evade AV. This is done by randomizing all WinAPI functions used, xor encoding strings, and utilizing basic sandbox checks. Mingw-w64 is used to compile the obfuscated C code into a DLL that can be loaded into any process where AMSI or ETW are present (i.e. PowerShell).

LightsOut is designed to work on Linux systems with `python3` and `mingw-w64` installed. No other dependencies are required.

Features currently include:
* XOR encoding for strings
* WinAPI function name randomization
* Multiple sandbox check options
* Hardware breakpoint bypass option

```
 _______________________
|                       |
|   AMSI + ETW          |
|                       |
|        LIGHTS OUT     |
|        _______        |
|       ||     ||       |
|       ||_____||       |
|       |/    /||       |
|       /    / ||       |
|      /____/ /-'       |
|      |____|/          |
|                       |
|          @icyguider   |
|                       |
|                     RG|
`-----------------------'
usage: lightsout.py [-h] [-m <method>] [-s <option>] [-sa <value>] [-k <key>] [-o <outfile>] [-p <pid>]

Generate an obfuscated DLL that will disable AMSI & ETW

options:
  -h, --help            show this help message and exit
  -m <method>, --method <method>
                        Bypass technique (Options: patch, hwbp, remote_patch) (Default: patch)
  -s <option>, --sandbox <option>
                        Sandbox evasion technique (Options: mathsleep, username, hostname, domain) (Default: mathsleep)
  -sa <value>, --sandbox-arg <value>
                        Argument for sandbox evasion technique (Ex: WIN10CO-DESKTOP, testlab.local)
  -k <key>, --key <key>
                        Key to encode strings with (randomly generated by default)
  -o <outfile>, --outfile <outfile>
                        File to save DLL to

Remote options:
  -p <pid>, --pid <pid>
                        PID of remote process to patch
```

**Intended Use/Opsec Considerations**

This tool was designed to be used on pentests, primarily to execute malicious powershell scripts without getting *blocked* by AV/EDR. Because of this, the tool is very barebones and a lot can be added to improve opsec. Do not expect this tool to completely evade detection by EDR.

**Usage Examples**

You can transfer the output DLL to your target system and load it into powershell various ways. For example, it can be done via P/Invoke with LoadLibrary:

![image](https://github.com/icyguider/LightsOut/assets/79864975/75358813-e1bf-4a2b-8059-d539ac97c510)

Or even easier, copy powershell to an arbitrary location and side load the DLL!

![image](https://github.com/icyguider/LightsOut/assets/79864975/e79c8cca-5e4e-4fb8-a4b5-4b888006b4cf)

**Greetz/Credit/Further Reference:**
* [@RastaMouse](https://twitter.com/_RastaMouse) for their blog post on patching AMSI: https://rastamouse.me/memory-patching-amsi-bypass/
* [@CCob/EthicalChaos](https://twitter.com/_EthicalChaos_) for their blog post on patchless AMSI bypasses via hardware breakpoints: https://ethicalchaos.dev/2022/04/17/in-process-patchless-amsi-bypass/
* [@rad9800](https://twitter.com/rad9800) for their code which this tool uses to bypass AMSI and ETW with hardware breakpoints: https://github.com/rad9800/misc/tree/main/hooks
