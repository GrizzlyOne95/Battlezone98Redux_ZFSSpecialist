import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import os
import sys
from ctypes import *

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
    lzo_dll.lzo_init_dll()
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
    def xor_data(self, data, key):
        if key == 0: return data
        data_map = bytearray(data)
        key_bytes = struct.pack('<I', int(key))
        for i in range(len(data_map)):
            data_map[i] ^= key_bytes[i % 4]
        return bytes(data_map)

    # --- CORE LOGIC: EXPLORER ---
    def open_zfs(self):
        path = filedialog.askopenfilename(filetypes=[("ZFS Archives", "*.zfs")])
        if not path: return
        self.current_zfs_path = path
        self.all_records = []
        
        with open(path, 'rb') as f:
            h = struct.unpack('<4sIIIIII', f.read(28))
            self.header_info = {'name_len': h[2], 'entries': h[3], 'total': h[4], 'key': h[5]}
            
            next_tab = h[6]
            while next_tab != 0 and len(self.all_records) < h[4]:
                f.seek(next_tab)
                next_tab = struct.unpack('<i', f.read(4))[0]
                for _ in range(h[3]):
                    if len(self.all_records) >= h[4]: break
                    fmt = f'<{h[2]}siiiii'
                    name_raw, offset, rnum, c_size, time, flags = struct.unpack(fmt, f.read(struct.calcsize(fmt)))
                    name = name_raw.split(b'\x00')[0].decode('ascii', errors='ignore').strip()
                    
                    self.all_records.append({
                        'name': name, 'ext': os.path.splitext(name)[1].lower(),
                        'size': flags >> 8, 'packed': c_size,
                        'method': "LZO1X" if (flags & 0x2) else "LZO1Y" if (flags & 0x4) else "Raw",
                        'offset': offset, 'flags': flags
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

        with open(self.current_zfs_path, 'rb') as f:
            for item in items:
                name = self.tree.item(item)['values'][0]
                rec = next(r for r in self.all_records if r['name'] == name)
                
                f.seek(rec['offset'])
                data = f.read(rec['packed'])
                
                if self.enc_var.get():
                    data = self.xor_data(data, self.header_info['key'])

                if rec['method'] != "Raw" and lzo_dll:
                    algo = 2 if (rec['flags'] & 0x0002) else 4
                    dst = create_string_buffer(rec['size'])
                    d_len = c_ulonglong(rec['size'])
                    lzo_dll.decompress_buffer(algo, data, c_ulonglong(rec['packed']), dst, byref(d_len))
                    content = dst.raw[:d_len.value]
                else:
                    content = data

                with open(os.path.join(out_dir, name), 'wb') as out_f:
                    out_f.write(content)
        messagebox.showinfo("Done", f"Extracted {len(items)} files.")

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
                d_len = c_ulonglong(max_c)
                lzo_dll.compress_buffer(raw_data, c_ulonglong(u_size), dst, byref(d_len))
                
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
