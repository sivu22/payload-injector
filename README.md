# What is payload-injector?
This small tool that I wrote a while ago allows for data injection into a signed Windows executable (PE format) without breaking the Authenticode digital signature. After signing an executable, every change brought to its data will invalidate the digital signature.

# Why then?
This is very useful when you have to deal with multi-platform programs and systems. One very common use case is a server who distributes client programs for the Windows platform.<br>
<br>
For a seamless integration and improved UX, one could provide everything in one package that the user downloads and installs on his machine. All this without further complications like multiple download files or installations, more protocols and communication, extra configuring or bringing additional computation to the server (i.e. building Windows executables).

# Solution
1. Build the Windows client/application installer natively - NSIS is perfect for the job - and sign it (it's a must for every executable!).
2. Bring the signed binary on to the server.
3. Every time a user wants to download a customized installer, usually including a configuration or specific settings, payload-injector can add the extra data to the default installer without invalidating the digital signature.
4. On the client machine, the user installs the program and the configuration at the same time - easy and fast. This can be achieved with a NSIS plugin which extracts the payload at installation-time.

# Usage
<code>pi.pl signed_exec_file payload_file result_file [--paddata]</code>

# Implementation details
- Although the paddata parameter is optional, it should be nevertheless used since the payload might not be a multiple of 8. Not using it will most probably result in a warning and a bad end-result.
- The payload gets injected at the end of the executable, after the Authenticode part.
- After injection, the PE header checksum will be updated accordingly.
