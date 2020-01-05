# vulnmath

file: `#x86`  
vuln: `#`  
soln: `#`  
  
* File
```sh
$ file vulnmath 
vulnmath: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=ba48ed39bdaaa3ddfc1bab6e8f45c8ee92e552bc, not stripped
```
  
* checksec.sh
```sh
$ checksec.sh --file vulnmath 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    Not an ELF file   No RPATH   RUNPATH      vulnmath
```
  
* exploit
```python

```
