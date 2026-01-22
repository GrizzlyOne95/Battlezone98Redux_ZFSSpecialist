# Battlezone ZFS Specialist

A high-performance archive explorer and packer for Battlezone (1998) `.zfs` files. This tool allows modders to browse, search, extract, and create encrypted/compressed archives compatible with the BZ1 engine.

## Features
* **Full Explorer:** Browse archive contents without extracting first.
* **Instant Search:** Filter thousands of files by name or extension in real-time.
* **Smart Packing:** Build new ZFS archives with LZO1X-1 compression.
* **XOR Crypto:** Full support for BZ1's rolling-key encryption.
* **Portable:** Standalone EXE (no Python installation required).

* <img width="1002" height="732" alt="image" src="https://github.com/user-attachments/assets/709805d7-14cf-40d2-9237-9acd845f2b0f" />


## Installation & Usage
1. Download the latest `zfs_specialist.exe` from the Releases tab.
3. **To Extract:** Open a ZFS, select files (multi-select supported), and click Extract.
4. **To Pack:** Go to the Packer tab, select a folder of files, set your XOR key, and build.

## Repository Structure
* `/src`: Python source code for the GUI and logic.
* `/dll_source`: C++ source code for the LZO bridge DLL.
* `/lib`: Original LZO library headers and references.
* `zfs.ico`: Custom application icon.

## Credits & Acknowledgments
* **GrizzlyOne95**: Developer.
* **Blake**: Inspiration and original logic from the `UnZFS` project.
* **Markus F.X.J. Oberhumer**: Author of the [LZO Real-Time Data Compression Library](http://www.oberhumer.com/opensource/lzo/).
* **The BZ1 Community**: For keeping the 1998 classic alive.

## License
This project is licensed under the **GNU General Public License v2.0 (GPL-2.0)**. 
As this tool utilizes the LZO library (GPL), the source code for this tool and its bridge are provided freely to remain compliant with LZO's licensing terms.

## Disclaimer
This tool is provided "as-is" without warranty of any kind. It is a fan-made project and is not affiliated with Activision or Rebellion.
