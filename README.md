Process Hollowing - injection technique that is injecting PE payloads into the address space of a remote process. 
The remote process is often a suspended child process created by the process hollowing implementation.
A typical process hollowing implementation generally creates a suspended process via the CreateProcess WinAPI and 
then calls NtUnmapViewOfSection to unmap the legitimate process image of the remote process. 
Once that's done, NtMapViewOfSection is called to map the PE payload's binary image instead.
Process Hollowing is a widely used technique and therefore can be more likely detected by security solutions. 
It is advised to use Process Ghosting or Herpaderping which are covered in upcoming modules.
The image below from Process Doppelgänging meets Process Hollowing in Osiris dropper illustrates Process Hollowing.

Into this implementation I added Process Enumeration with NtQuerySystemInformation, Spoofing PPID and Spoofing Arguments.
