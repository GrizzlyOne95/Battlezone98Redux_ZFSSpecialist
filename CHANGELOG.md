# Changelog

## 2026-03-05

- Added BZ-themed UI styling aligned with Battlezone98Redux_GOGModDownloader:
  - dark panel backgrounds
  - cyan/blue accent and highlight colors
  - styled notebook tabs, buttons, entries, treeview, headings, and progress bar
- Updated explorer/packer labels and status bar presentation to match the BZ HUD-like look.

## 2026-03-05

- Fixed encrypted archive extraction so MakeZFS-style content now exports correctly.
- Removed incorrect packed/unpacked size mutation based on encrypted data prefixes.
- Corrected decrypt/decompress order for encrypted compressed files:
  - old behavior: decrypt packed block, then decompress
  - new behavior: decompress packed block, then XOR decoded payload
- Updated manual key parsing to accept decimal and hex integer input (`int(..., 0)`).
- Updated password handling to use `CRC32(password)` as the effective 32-bit XOR key.
- Updated `README.md` with key entry and encrypted extraction behavior notes.
