# VT Context Scanner

VT Context Scanner is a Firefox extension that adds a link context-menu action for checking URLs with VirusTotal before you open them.

## Features

- Adds `Scan Link with VirusTotal` to Firefox's link context menu
- Uses your own VirusTotal API key
- Opens the popup automatically while a scan runs
- Updates the toolbar badge with scan status and results

## Requirements

- Firefox 142 or newer
- A VirusTotal API key

## Run Locally

1. Install `web-ext` if you do not already have it.
2. Start Firefox with the extension loaded from this folder:

```bash
web-ext run --firefox=/Applications/Firefox.app/Contents/MacOS/firefox-bin
```

3. Open the extension settings and save your VirusTotal API key.
4. Right-click any link and choose `Scan Link with VirusTotal`.
5. The popup opens automatically and shows the scan result when it arrives.

## Build

To create a distributable archive:

```bash
web-ext build --overwrite-dest
```

The built package is written to `web-ext-artifacts/`.

## Permissions

This extension requests the following permissions:

- `contextMenus` to add the link scan action
- `storage` to save your VirusTotal API key and the most recent result
- Host access to `https://www.virustotal.com/api/v3/*` to talk to the VirusTotal API

## Privacy And Security

- The VirusTotal API key is stored locally in Firefox extension storage.
- The extension only sends a URL to VirusTotal when you explicitly choose to scan it.
- The extension does not send data to any developer-owned backend.
- No analytics or advertising services are used.
- No hardcoded API keys or other secrets are stored in the repository.

## Development Checks

Run the Firefox extension linter before publishing changes:

```bash
web-ext lint
```
