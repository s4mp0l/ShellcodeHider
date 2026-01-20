# ShellcodeHider

ShellcodeHider is an open source tool developed in C that encrypts and/or obfuscates raw shellcode.

<img width="942" height="338" alt="image" src="https://github.com/user-attachments/assets/d33d0fd7-1006-4194-8987-4925febadbc6" />
<br></br>

> This tool is not finished. Check the to-do section for more information.

## Features

It encrypts and/or obfuscates the shellcode that is passed through a .bin file and returns the decryption or deobfuscation routine to the console to restore the shellcode to its original state.

The decryption/deobfuscation routine returned to the console contains the encrypted shellcode, keys used, and functions used to decrypt/deobfuscate the shellcode.

In addition to printing the decryption routine, it is also possible to save the encrypted shellcode in a file and use it in conjunction with the decryption/deobfuscation routine printed on the console.

> At the moment, this tool is specifically designed for C.

ShellcodeHider supports the following encryption algorithms:

- **Aes:** BCrypt library && TinyAes library
- **ChaCha20**
- **Rc4:** Custom Rc4 && Rc4 via SystemFunction033
- **Xor**

It also supports the following obfuscation methods:

- **IPv4 Addresses:** Transform Shellcode into IPv4 Addresses
- **IPv6 Addresses:** Transform Shellcode into IPv6 Addresses
- **Mac Addresses:** Transform Shellcode into Mac Addresses
- **UUID format:** Transform Shellcode into UUID format
- **Timestamp format:** Transform Shellcode into Timestamps format

## TODO

Future implementations:

- New encryption/obfuscation methods
- Adapt ShellcodeHider for languages other than C
- Allow selection of encryption keys
- Allow selection of whether to print only the shellcode or the decryption/deobfuscation routine

## Contributions

The code in this repository may contain bugs. If anyone is interested in contributing or fixing any errors, please feel free to contact me [here](https://linktr.ee/JuliDruetto) or submit a pull request :)

## Reference / Resources

- [TinyAes](https://github.com/kokke/tiny-AES-c)
- [phase.dev AES && ChaCha20](https://phase.dev/blog/chacha-and-aes-simplicity-in-cryptography/)
- [Maldevcademy](https://maldevacademy.com/)
- [oryx-embedded ChaCha20 in C](https://www.oryx-embedded.com/doc/chacha_8c_source.html)
- [ReactOS](https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725)
- [Hive Ransomware IPfuscation blog by Sentinelone](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
