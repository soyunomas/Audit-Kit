# 🐚 Go Reverse Shell Generator

![Go Version](https://img.shields.io/badge/Go-1.20%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Fyne](https://img.shields.io/badge/GUI-Fyne-orange?style=for-the-badge&logo=codeigniter&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-gray?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

## 📄 Description

**Go Reverse Shell Generator** is a powerful, standalone desktop application designed for generating reverse shell payloads offline. Rewritten entirely in **Go (Golang)** using the **Fyne** toolkit, this tool is tailored for Penetration Testers, Red Teamers, and CTF players who require a reliable payload generator without internet access.

It serves as a compiled, portable, and secure alternative to online tools like [revshells.com](https://revshells.com), offering zero runtime dependencies (no Python or interpreters required on the host machine).

![App Screenshot](screenshot.png)

## ✨ Features

### 🐧 Linux / Unix / Web
- **Bash:** Classic `-i`, generic TCP, UDP, and file descriptor variants (196, 5).
- **Netcat:** Support for `mkfifo`, `-e`, `-c`, and `ncat` SSL.
- **Web Shells:** Ready-to-use PHP (PentestMonkey, `system`, `exec`), JSP, and ASPX.
- **Scripting Languages:** Python (2/3), Perl, Ruby, NodeJS, Lua.
- **Compiled/Misc:** Golang, Socat (TTY), OpenSSL, Awk, Telnet.

### 🪟 Windows
- **PowerShell:** TCP Stream, Base64 Encoded payloads, IEX (DownloadString), and ConPtyShell (Fully Interactive).
- **Binaries:** `nc.exe`, `ncat.exe`.
- **Living off the Land (LOLBins):** MSBuild, Mshta, Regsvr32.
- **C# / .NET:** Native TCP Client and Process Injection vectors.

## 🛠️ Tech Stack

- **Language:** Go (Golang) 1.20+
- **GUI Framework:** Fyne Toolkit
- **Architecture:** Native Binary (Cross-Platform)

## 🚀 Installation & Build

Since this application uses Fyne for the GUI, it requires a C Compiler for GPU interface bindings.

### 1. Prerequisites
*   **Go 1.20+**: [Download Go](https://go.dev/dl/)
*   **C Compiler (GCC)**:
    *   **Debian/Ubuntu:**
        ```bash
        sudo apt install gcc libgl1-mesa-dev xorg-dev
        ```
    *   **Windows:** Install [TDM-GCC](https://jmeubank.github.io/tdm-gcc/).
    *   **macOS:** Install Xcode Command Line Tools (`xcode-select --install`).

### 2. Clone & Initialize
```bash
git clone https://github.com/soyunomas/go-revshell.git
cd go-revshell
go mod tidy
```

### 3. Build

**For Linux / macOS:**
```bash
go build -o revshell-gen .
```

**For Windows:**
To build a `.exe` that hides the console window on startup:
```bash
go build -ldflags -H=windowsgui -o revshell-gen.exe .
```

## 💻 Usage

1.  **Launch:** Run the compiled binary (`./revshell-gen` or `revshell-gen.exe`).
2.  **Configuration:**
    *   **LHOST:** Input your attacking IP (VPN, Tun0, or local IP).
    *   **LPORT:** Input the listening port.
3.  **Selection:**
    *   Choose the Target OS (Linux/Windows).
    *   Select the Payload strategy from the dropdown.
    *   *Tip:* Check the **"Payload Details"** panel for OPSEC warnings and stability info.
4.  **Encoding (Optional):** Toggle Base64 if you are injecting into a filtered input field.
5.  **Execute:**
    *   Copy & Run the **Listener** command on your machine.
    *   Copy & Inject the **Payload** into the target.

## 📁 Project Structure

The project is structured to separate GUI logic from payload data, allowing for easy expansion without conflicts.

```text
go-revshell/
├── main.go             # GUI Logic, Event Handling, Encoding
├── metadata.go         # Help text, OPSEC warnings, and Tips database
├── payloads_lin.go     # Map of Linux/Unix payloads
├── payloads_win.go     # Map of Windows payloads
├── go.mod              # Go module definition
└── README.md           # Documentation
```

## 🤝 Contributing

Contributions are welcome! If you want to add a new shell technique:

1.  **Add the Code:** Open `payloads_lin.go` or `payloads_win.go` and add the raw string to the map.
2.  **Add the Metadata:** Open `metadata.go` and add the description, stability rating, and usage tips.
3.  **Submit:** Create a Pull Request.

**Example entry in `metadata.go`:**
```go
"MyNewShell": {
    Description: "Uses a specific binary found in legacy systems.",
    OpSec:       "🟢 Stealthy - Low detection rate",
    Consejo:     "Use port 443 to blend in with HTTPS traffic.",
},
```

## ⚠️ Legal Disclaimer

```text
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE AND AUTHORIZED SECURITY ASSESSMENTS ONLY.

1. Do not use this tool on systems you do not own or have explicit permission to test.
2. The authors are not responsible for any damage or illegal use.
3. Misuse of this software violates local and international laws.
```

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.
