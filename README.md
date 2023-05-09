# parallels-plist-escape

This repository contains exploits for CVE-2023-27327 and CVE-2023-27328, which can be used together to escape a Parallels Desktop virtual machine, prior to Parallels Desktop 18.1.1. 

It also contains code for a required kernel module, in `prl_mod`, which can be used to send arbitrary Toolgate requests (< opcode 0x8000) from userland, using a proc entry created at `/proc/driver/prl_tg_pwn`.

### Requirements
- Root in the guest so you can load the kernel module
- Parallels Tools installed - this is not strictly required if we have root in the guest, but the code here assumes it's present
- At least one share mounted into the VM, it doesn't matter where this is on the host

### Running the exploit
Build and load the kernel module:
```bash
cd prl_mod
make -f Makefile.kmods
sudo insmod ./prl_tg_pwn/Toolgate/Guest/Linux/prl_tg/prl_tg_pwn.ko
```

Run the exploit:
```bash
cd ..
pip install -r requirements.txt
./3_full_chain.py
```
