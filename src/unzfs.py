import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import os
import sys
from ctypes import *
import zlib

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- DLL Integration (SINGLE BLOCK) ---
try:
    dll_path = resource_path('lzo_bridge.dll')
    lzo_dll = WinDLL(dll_path)
    
    # Define signatures to match bridge.cpp (lzo_uint -> c_size_t)
    lzo_dll.lzo_init_dll.restype = c_int
    
    lzo_dll.compress_buffer.argtypes = [c_void_p, c_size_t, c_void_p, POINTER(c_size_t)]
    lzo_dll.compress_buffer.restype = c_int
    
    lzo_dll.decompress_buffer.argtypes = [c_int, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)]
    lzo_dll.decompress_buffer.restype = c_int
    
    if lzo_dll.lzo_init_dll() != 0:
        print("LZO Init failed")
        lzo_dll = None
except Exception as e:
    lzo_dll = None
    print(f"Critical: DLL not found. {e}")

class ZFSManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Battlezone ZFS Specialist v3.0")
        self.root.geometry("1000x700")
        
        # Set Window Icon (The taskbar/titlebar icon)
        try:
            self.root.iconbitmap(resource_path("zfs.ico"))
        except Exception:
            pass 
        
        # Internal Data
        self.current_zfs_path = ""
        self.all_records = []
        self.header_info = {}
        self.sort_reverse = False

        # Build Tabs
        self.tabs = ttk.Notebook(root)
        self.tab_browse = ttk.Frame(self.tabs)
        self.tab_pack = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_browse, text="🔍 Archive Explorer")
        self.tabs.add(self.tab_pack, text="📦 ZFS Packer")
        self.tabs.pack(expand=1, fill="both")

        self.setup_explorer_ui()
        self.setup_packer_ui()

    # --- UI: EXPLORER TAB ---
    def setup_explorer_ui(self):
        # Create Menu Bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Add Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="How to Use", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)

        # Top Controls
        top = tk.Frame(self.tab_browse)
        top.pack(side="top", fill="x", padx=10, pady=10)
        
        tk.Button(top, text="📂 Open ZFS", command=self.open_zfs, width=15).pack(side="left")
        tk.Button(top, text="📥 Extract Selected", command=self.extract_selected, bg="#c8e6c9", width=15).pack(side="left", padx=5)
        
        self.enc_var = tk.BooleanVar(value=True)
        tk.Checkbutton(top, text="Apply Header Decryption Key", variable=self.enc_var).pack(side="left", padx=10)
        
        self.dir_enc_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="Decrypt Directory", variable=self.dir_enc_var).pack(side="left", padx=5)
        
        tk.Label(top, text="Manual Key Override:").pack(side="left", padx=(10, 2))
        self.manual_key_var = tk.StringVar(value="")
        tk.Entry(top, textvariable=self.manual_key_var, width=12).pack(side="left")

        # Search Bar
        search_frame = tk.Frame(self.tab_browse)
        search_frame.pack(side="top", fill="x", padx=10, pady=5)
        tk.Label(search_frame, text="Filter:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.refresh_tree())
        tk.Entry(search_frame, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=5)

        # Treeview
        list_frame = tk.Frame(self.tab_browse)
        list_frame.pack(expand=True, fill="both", padx=10, pady=5)
        
        cols = ("name", "ext", "size", "packed", "method")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings", selectmode="extended")
        
        headings = {"name": "File Name", "ext": "Ext", "size": "Original Size", "packed": "Packed Size", "method": "Method"}
        for col, text in headings.items():
            self.tree.heading(col, text=f"{text} ↕", command=lambda c=col: self.sort_column(c))
        
        self.tree.column("ext", width=50, anchor="center")
        self.tree.column("size", width=100, anchor="e")
        self.tree.column("packed", width=100, anchor="e")
        
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", expand=True, fill="both")
        scroll.pack(side="right", fill="y")

        self.ex_status = tk.Label(self.tab_browse, text="Ready", bd=1, relief="sunken", anchor="w")
        self.ex_status.pack(side="bottom", fill="x")

    def show_help(self):
        help_text = (
            "1. Open a .zfs file to browse contents.\n"
            "2. Use the Search bar to filter by extension (e.g., .odf).\n"
            "3. Select files (Ctrl+Click) and hit Extract.\n\n"
            "4. This tool supports experimental encryption breaking.\nAn encrypted ZFS should be able to still be extracted."
            "Note: Packing requires a folder of files. The tool will "
            "automatically compress them using LZO1X-1."
        )
        messagebox.showinfo("How to Use", help_text)

    def show_about(self):
        about_text = (
            "Battlezone ZFS Tool v3.0\n"
            "Developed by GrizzlyOne95\n\n"
            "Credits:\n"
            "- Inspiration: Blake for his work on UnZFS\n"
            "- LZO Compression: Markus F.X.J. Oberhumer\n"
            "- ZFS Logic: Based on BZ1 Game Code\n\n"
            "This tool is provided as-is for the BZ1 Modding Community."
        )
        messagebox.showinfo("About", about_text)

    # --- UI: PACKER TAB ---
    def setup_packer_ui(self):
        main = tk.Frame(self.tab_pack)
        main.pack(expand=True)
        
        tk.Label(main, text="Pack Folder into ZFS", font=("Arial", 12, "bold")).pack(pady=10)
        
        tk.Label(main, text="Encryption Key (Numeric):").pack()
        self.pk_key_entry = tk.Entry(main, justify="center")
        self.pk_key_entry.insert(0, "0")
        self.pk_key_entry.pack(pady=5)
        
        tk.Button(main, text="🚀 Select Folder & Build ZFS", command=self.pack_folder, 
                  height=2, width=30, bg="#bbdefb").pack(pady=20)
        
        self.pk_progress = ttk.Progressbar(main, length=300, mode='determinate')
        self.pk_progress.pack(pady=10)
        self.pk_status = tk.Label(main, text="Waiting for input...")
        self.pk_status.pack()

    # --- CORE LOGIC: CRYPTO ---
    def get_manual_key(self):
        val = self.manual_key_var.get().strip()
        if not val: return None
        try:
            return int(val)
        except ValueError:
            # Assume string password
            return val

    def build_key_stream(self, key_val):
        if not key_val:
            return b""
        if isinstance(key_val, int):
            return struct.pack('<I', key_val & 0xFFFFFFFF)
        
        # It's a string password
        pwd_bytes = key_val.encode('utf-8')
        header_key = zlib.crc32(pwd_bytes) & 0xFFFFFFFF
        h_bytes = struct.pack('<I', header_key)
        
        # The repeating key structure: [len(password)] + header_key_bytes + password_bytes
        return bytes([len(pwd_bytes)]) + h_bytes + pwd_bytes

    def xor_data(self, data, key_val):
        key_stream = self.build_key_stream(key_val)
        if not key_stream: return data
        
        res = bytearray(len(data))
        k_len = len(key_stream)
        for i in range(len(data)):
            res[i] = data[i] ^ key_stream[i % k_len]
        return bytes(res)

    # --- CORE LOGIC: EXPLORER ---
    def open_zfs(self):
        path = filedialog.askopenfilename(filetypes=[("ZFS Archives", "*.zfs")])
        if not path: return
        self.current_zfs_path = path
        self.all_records = []
        
        with open(path, 'rb') as f:
            h = struct.unpack('<4sIIIIII', f.read(28))
            self.header_info = {'name_len': h[2], 'entries': h[3], 'total': h[4], 'key': h[5]}
            print(f"[Open] Header Info: {self.header_info}")
            
            # Determine Key for Directory (if needed)
            dir_key = self.header_info['key']
            man_key = self.get_manual_key()
            if man_key is not None: dir_key = man_key
            
            next_tab = h[6]
            limit = h[4]
            
            # Fix for malformed headers where total is 0 but content exists
            if limit == 0 and next_tab != 0:
                print("[Open] Warning: Header reports 0 files but has data pointer. Ignoring limit.")
                limit = 999999999

            f.seek(0, os.SEEK_END)
            f_size = f.tell()

            # Check if initial next_tab (h[6]) is encrypted
            if next_tab >= f_size and dir_key != 0:
                try:
                    dec_next = struct.unpack('<I', self.xor_data(struct.pack('<I', next_tab), dir_key))[0]
                    if dec_next < f_size:
                        print(f"[Open] Detected encrypted directory pointer. Decrypted {next_tab} -> {dec_next}")
                        next_tab = dec_next
                except Exception as e:
                    print(f"[Open] Failed to decrypt initial pointer: {e}")

            while next_tab != 0 and len(self.all_records) < limit:
                if next_tab < 0 or next_tab >= f_size:
                    print(f"[Open] Invalid next_tab pointer: {next_tab}. Stopping.")
                    break
                f.seek(next_tab)
                
                # Read Block Header
                b_head = f.read(4)
                if len(b_head) < 4: break
                
                # Check if block header is encrypted
                raw_next = struct.unpack('<I', b_head)[0]
                block_encrypted = False
                
                if self.dir_enc_var.get() or (raw_next >= f_size and dir_key != 0):
                    dec_head = self.xor_data(b_head, dir_key)
                    dec_next = struct.unpack('<I', dec_head)[0]
                    if dec_next == 0 or dec_next < f_size:
                        b_head = dec_head
                        next_tab = dec_next
                        block_encrypted = True
                    else:
                        next_tab = raw_next
                else:
                    next_tab = raw_next
                
                for _ in range(h[3]):
                    if len(self.all_records) >= limit: break
                    fmt = f'<{h[2]}sIIIII'
                    rec_size = struct.calcsize(fmt)
                    chunk = f.read(rec_size)
                    if len(chunk) < rec_size: break
                    
                    if block_encrypted:
                        chunk = self.xor_data(chunk, dir_key)

                    name_raw, offset, rnum, c_size, time, flags = struct.unpack(fmt, chunk)
                    if block_encrypted:
                        chunk = self.xor_data(chunk, dir_key)
                        name_raw, offset, rnum, c_size, time, flags = struct.unpack(fmt, chunk)

                    name = name_raw.split(b'\x00')[0].decode('ascii', errors='ignore').strip()
                    
                    if not name: 
                        continue

                    # Handle "Retarded" Encryption: Fix Sizes
                    u_size = flags >> 8
                    p_size = c_size
                    is_encrypted = self.header_info['key'] != 0
                    
                    if is_encrypted:
                        curr_pos = f.tell()
                        f.seek(offset)
                        prefix = f.read(1)
                        if prefix:
                            # prefix[0] is used both as XOR byte and to adjust sizes
                            p_byte = prefix[0]
                            p_size ^= p_byte
                            u_size ^= p_byte
                        f.seek(curr_pos)

                    self.all_records.append({
                        'name': name, 'ext': os.path.splitext(name)[1].lower(),
                        'size': u_size, 'packed': p_size,
                        'method': "LZO1X" if (flags & 0x2) else "LZO1Y" if (flags & 0x4) else "Raw",
                        'offset': offset, 'flags': flags,
                        'encrypted': is_encrypted
                    })
        self.refresh_tree()

    def refresh_tree(self):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        for r in self.all_records:
            if query in r['name'].lower():
                self.tree.insert("", "end", values=(r['name'], r['ext'], r['size'], r['packed'], r['method']))
        self.ex_status.config(text=f"Archive: {os.path.basename(self.current_zfs_path)} | Files: {len(self.all_records)}")

    def sort_column(self, col):
        self.sort_reverse = not self.sort_reverse
        self.all_records.sort(key=lambda x: x[col], reverse=self.sort_reverse)
        self.refresh_tree()

    def extract_selected(self):
        items = self.tree.selection()
        if not items or not self.current_zfs_path: return
        out_dir = filedialog.askdirectory()
        if not out_dir: return

        count = 0
        with open(self.current_zfs_path, 'rb') as f:
            for item in items:
                name = self.tree.item(item)['values'][0]
                rec = next(r for r in self.all_records if r['name'] == name)
                
                f.seek(rec['offset'])
                
                # Determine Key
                use_key = self.header_info['key']
                man_key = self.get_manual_key()
                if man_key is not None: use_key = man_key

                is_encrypted = rec.get('encrypted', False)
                
                if is_encrypted:
                    # Skip the "Retarded" 2-byte prefix
                    f.read(2)
                    data = f.read(rec['packed'])
                else:
                    data = f.read(rec['packed'])
                
                print(f"[Extract] File: {name} | Offset: {rec['offset']} | Packed: {rec['packed']} | Unpacked: {rec['size']} | Key: {use_key} | Enc: {is_encrypted}")

                if man_key is not None: key = man_key
                else: key = use_key

                # Get record details
                offset = rec['offset']
                p_size = rec['packed']
                u_size = rec['size']
                flags = rec['flags']
                
                f.seek(offset)
                
                # Decrypt: BZ98 Redux repeating XOR key mechanism
                # Initial 2 bytes are NOT part of data but ARE XORed
                if key != 0 and key != "":
                    encrypted_data = f.read(p_size + 2)
                    decrypted_block = self.xor_data(encrypted_data, key)
                    data = decrypted_block[2:] # Skip the 2-byte prefix
                else:
                    data = f.read(p_size)
                
                # Decompress
                if (flags & 0x6) and lzo_dll:
                    # ZFS uses LZO1X or LZO1Y.
                    # LZO_ALGO_1X = 2, LZO_ALGO_1Y = 4
                    algo = 2 if (flags & 0x0002) else 4
                    
                    # u_size in ZFS usually reflects the final size.
                    # Provide a reasonable buffer size for decompression,
                    # as u_size might be incorrect in some malformed ZFS files.
                    dst_size = max(u_size, 10 * 1024 * 1024) 
                    dst = create_string_buffer(dst_size + 4096) # Add padding
                    d_len = c_size_t(u_size) # Expected decompressed length

                    try:
                        ret = lzo_dll.decompress_buffer(algo, data, c_size_t(len(data)), dst, byref(d_len))
                        if ret == 0: # LZO_E_OK
                            content = dst.raw[:d_len.value]
                        else:
                            print(f"Decompression error {ret} for {name}")
                            content = data # Fallback to packed if decompression fails
                    except Exception as e:
                        print(f"Decompression crash for {name}: {e}")
                        content = data # Fallback to packed if decompression crashes
                else:
                    content = data

                out_path = os.path.join(out_dir, name)
                with open(out_path, 'wb') as out_f:
                    out_f.write(content)
                
                count += 1
        messagebox.showinfo("Done", f"Extracted {count} files.")

    def pack_folder(self):
        in_dir = filedialog.askdirectory(title="Source Folder")
        if not in_dir: return
        out_zfs = filedialog.asksaveasfilename(defaultextension=".zfs")
        if not out_zfs: return
        
        files = [f for f in os.listdir(in_dir) if os.path.isfile(os.path.join(in_dir, f))]
        self.pk_progress['maximum'] = len(files)
        key = int(self.pk_key_entry.get())

        with open(out_zfs, 'wb') as f:
            f.write(b'\x00' * 28) 
            records = []
            for i, fname in enumerate(files):
                with open(os.path.join(in_dir, fname), 'rb') as in_f:
                    raw_data = in_f.read()
                
                u_size = len(raw_data)
                max_c = u_size + (u_size // 16) + 64 + 3
                dst = create_string_buffer(max_c)
                d_len = c_size_t(max_c)
                lzo_dll.compress_buffer(raw_data, c_size_t(u_size), dst, byref(d_len))
                
                final_data = self.xor_data(dst.raw[:d_len.value], key)
                offset = f.tell()
                f.write(final_data)
                
                flags = (u_size << 8) | 0x0002 
                records.append((fname.encode('ascii')[:15], offset, i, d_len.value, 0, flags))
                
                self.pk_progress['value'] = i + 1
                self.pk_status['text'] = f"Packing: {fname}"
                self.root.update()

            head_ptr = f.tell()
            for i in range(0, len(records), 100):
                batch = records[i:i+100]
                nxt = f.tell() + 3604 if (i+100 < len(records)) else 0
                f.write(struct.pack('<i', nxt))
                for r in batch:
                    f.write(struct.pack('<16siiiii', r[0], r[1], r[2], r[3], r[4], r[5]))
                if len(batch) < 100: f.write(b'\x00' * (36 * (100 - len(batch))))

            f.seek(0)
            f.write(struct.pack('<4sIIIIII', b'ZFSF', 1, 16, 100, len(files), key, head_ptr))

        messagebox.showinfo("Success", "ZFS Built Successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = ZFSManager(root)
    root.mainloop()
