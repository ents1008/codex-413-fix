# Codex 413 Fix

[![Build](https://github.com/ents1008/codex-413-fix/actions/workflows/build.yml/badge.svg)](https://github.com/ents1008/codex-413-fix/actions/workflows/build.yml)

Remove selected image attachments from local Codex conversations when accumulated
images make the next request fail with `413 Payload Too Large`.

Codex 413 Fix runs entirely on your computer. It opens a browser interface on
`127.0.0.1`, reads only the local Codex index, creates a complete backup, and
then removes the images you selected from the conversation JSONL.

## Download and run

Download the archive for your platform from
[Releases](https://github.com/ents1008/codex-413-fix/releases/latest), extract it,
and open the included application. Python and `pip install` are not required.

| Platform | Release file | Start |
| --- | --- | --- |
| Windows x64 | `codex-413-fix-windows-x64.zip` | Double-click `codex-413-fix.exe` |
| macOS Apple Silicon | `codex-413-fix-macos-arm64.zip` | Open `Codex 413 Fix.app` |
| macOS Intel | `codex-413-fix-macos-x64.zip` | Open `Codex 413 Fix.app` |
| Linux x64 | `codex-413-fix-linux-x64.tar.gz` | Run `./codex-413-fix` |

Unsigned community builds may trigger Windows SmartScreen or macOS Gatekeeper.
On macOS, use Finder's **Open** command from the context menu the first time.
No additional runtime is installed.

## Usage

1. Copy the full Codex conversation UUID.
2. Open Codex 413 Fix and scan the conversation.
3. Select the images to remove.
4. Stop generation and tool calls in that conversation.
5. Confirm deletion. The original JSONL is backed up first.
6. Exit the old Codex process and reload the conversation with
   `codex resume <conversation-id>`.

The web page includes a power button that stops the local application cleanly.

## Data locations

The default Codex directory is `~/.codex`. Set `CODEX_HOME` before starting the
application when Codex uses another location.

Backups:

```text
~/.codex/backup/image-pruner/<conversation-id>/
```

Security audit log:

```text
~/.codex/log/codex-413-fix-audit.jsonl
```

The audit log contains identifiers, hashes, sizes, and backup paths. It does not
contain image data or message text.

## Safety model

- Binds only to the loopback interface.
- Accepts only loopback Host and Origin values.
- Protects all state-changing requests with an in-memory CSRF token.
- Resolves conversations through the Codex SQLite index instead of accepting a
  file path from the browser.
- Trusts JSONL files only under `sessions` and `archived_sessions` in
  `CODEX_HOME`.
- Rechecks size, modification time, and SHA-256 before changing a session.
- Writes and syncs a complete backup before replacing the original file.
- Preserves unmodified JSONL lines byte-for-byte.
- Refuses to modify a session that changed after scanning.

Codex does not currently expose a public API for deleting one historical image.
This tool repairs local persisted JSONL. A future Codex format change may require
an update; validation is designed to fail closed instead of guessing.

## Run from source

Python 3.11 or newer is required. The application itself uses only the Python
standard library.

```bash
python3 app.py
```

Windows PowerShell:

```powershell
.\run.ps1
```

macOS or Linux:

```bash
./run.sh
```

Use another port or skip opening the browser automatically:

```bash
python3 app.py --port 8877 --no-browser
```

## Test and build

```bash
python3 -m unittest discover -s tests -v
python3 -m pip install -r requirements-build.txt
pyinstaller --clean --noconfirm codex_413_fix.spec
```

GitHub Actions builds standalone packages for Windows x64, Linux x64, macOS
Intel, and macOS Apple Silicon. Tags matching `v*` publish all packages and a
`SHA256SUMS.txt` file to GitHub Releases.

## License

[MIT](LICENSE)
