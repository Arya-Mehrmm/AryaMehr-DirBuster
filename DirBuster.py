import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import requests
import random
from queue import Queue
from ttkthemes import ThemedTk

# A predefined pool of User-Agents for random selection
USER_AGENTS_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "curl/7.81.0"
]


class App(ThemedTk):
    def __init__(self):
        super().__init__(theme='arc')

        self.title("AryaMehr PyBuster")
        self.geometry("850x750")
        self.minsize(700, 600)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- State and Filter Variables ---
        self.is_scanning = False
        self.scan_thread = None
        self.processed_count = 0
        self.found_count = 0
        self.total_tasks = 0
        self.lock = threading.Lock()

        # --- NEW: A dedicated queue for all UI updates ---
        self.ui_update_queue = Queue()

        self.show_2xx_var = tk.BooleanVar(value=True)
        self.show_3xx_var = tk.BooleanVar(value=True)
        self.show_4xx_var = tk.BooleanVar(value=True)
        self.show_5xx_var = tk.BooleanVar(value=False)
        self.show_all_var = tk.BooleanVar(value=False)

        self._create_menu()
        self.create_widgets()

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def _create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results...", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        config_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        config_frame.columnconfigure(1, weight=1)

        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_var = tk.StringVar(value="http://127.0.0.1")
        self.url_entry = ttk.Entry(config_frame, textvariable=self.url_var)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

        ttk.Label(config_frame, text="Wordlist:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.wordlist_var = tk.StringVar()
        self.wordlist_entry = ttk.Entry(config_frame, textvariable=self.wordlist_var)
        self.wordlist_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.browse_btn = ttk.Button(config_frame, text="Browse...", command=self.browse_wordlist)
        self.browse_btn.grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(config_frame, text="Threads:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.threads_var = tk.IntVar(value=50)
        self.threads_spinbox = ttk.Spinbox(config_frame, from_=1, to=500, textvariable=self.threads_var, width=10)
        self.threads_spinbox.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        filter_frame = ttk.LabelFrame(main_frame, text="Filter Options", padding="10")
        filter_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=10)
        ttk.Checkbutton(filter_frame, text="2xx", variable=self.show_2xx_var).pack(side="left", padx=5)
        ttk.Checkbutton(filter_frame, text="3xx", variable=self.show_3xx_var).pack(side="left", padx=5)
        ttk.Checkbutton(filter_frame, text="4xx", variable=self.show_4xx_var).pack(side="left", padx=5)
        ttk.Checkbutton(filter_frame, text="5xx", variable=self.show_5xx_var).pack(side="left", padx=5)
        ttk.Separator(filter_frame, orient='vertical').pack(side="left", fill='y', padx=10, pady=5)
        ttk.Checkbutton(filter_frame, text="Show All (incl. 404)", variable=self.show_all_var).pack(side="left", padx=5)

        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.results_tree = ttk.Treeview(results_frame, columns=("Status", "URL"), show="headings")
        self.results_tree.heading("Status", text="Status Code")
        self.results_tree.heading("URL", text="Found Path")
        self.results_tree.column("Status", width=120, anchor="center", stretch=False)
        self.results_tree.column("URL", stretch=True)
        self.results_tree.tag_configure('status_2xx', foreground='green')
        self.results_tree.tag_configure('status_3xx', foreground='orange')
        self.results_tree.tag_configure('status_4xx', foreground='red')
        self.results_tree.tag_configure('status_5xx', foreground='purple')
        self.results_tree.tag_configure('status_other', foreground='gray')
        self.results_tree.bind("<Double-1>", self.copy_to_clipboard)

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=(10, 0))
        status_frame.columnconfigure(2, weight=1)
        self.start_btn = ttk.Button(status_frame, text="Start Scan", command=self.toggle_scan)
        self.start_btn.grid(row=0, column=0, padx=(0, 10))
        self.clear_btn = ttk.Button(status_frame, text="Clear Results", command=self.clear_results)
        self.clear_btn.grid(row=0, column=1, padx=(0, 10))
        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=0, column=2, sticky="ew")
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def copy_to_clipboard(self, event):
        selected_item = self.results_tree.focus()
        if not selected_item: return
        url_to_copy = self.results_tree.item(selected_item, "values")[1]
        self.clipboard_clear()
        self.clipboard_append(url_to_copy)
        original_status = self.status_var.get()
        self.status_var.set(f"Copied: {url_to_copy}")
        self.after(2000, lambda: self.status_var.set(original_status))

    def _get_selected_status_codes(self):
        codes = set()
        if self.show_2xx_var.get(): codes.update(range(200, 300))
        if self.show_3xx_var.get(): codes.update(range(300, 400))
        if self.show_4xx_var.get(): codes.update(range(400, 500))
        if self.show_5xx_var.get(): codes.update(range(500, 600))
        return codes

    def toggle_scan(self):
        if self.is_scanning:
            self.stop_scan()
        else:
            self.start_scan()

    def start_scan(self):
        url = self.url_var.get().rstrip('/')
        wordlist_path = self.wordlist_var.get()
        if not all([url, wordlist_path]):
            messagebox.showerror("Input Error", "Target URL and Wordlist must be provided.")
            return

        self.clear_results()
        self.is_scanning = True
        self.start_btn.config(text="Stop Scan")
        self.set_controls_state("disabled")

        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(url, wordlist_path, self.threads_var.get(), self._get_selected_status_codes()),
            daemon=True
        )
        self.scan_thread.start()
        self.process_ui_updates()  # Start the UI update loop

    def stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.status_var.set("Stopping...")

    def run_scan(self, url, wordlist_path, num_threads, status_codes_to_show):
        task_queue = Queue()
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
                self.total_tasks = len(words)
                for word in words: task_queue.put(word)
        except FileNotFoundError:
            self.ui_update_queue.put(('error', "File Error", f"Wordlist not found at: {wordlist_path}"))
            return

        def worker():
            while self.is_scanning and not task_queue.empty():
                try:
                    path = task_queue.get_nowait()
                except Queue.Empty:
                    continue

                full_url = f"{url}/{path}"
                headers = {'User-Agent': random.choice(USER_AGENTS_POOL)}
                try:
                    res = requests.get(full_url, headers=headers, timeout=10, allow_redirects=False)
                    if self.show_all_var.get() or res.status_code in status_codes_to_show:
                        self.ui_update_queue.put(('result', res.status_code, full_url))
                except requests.RequestException:
                    pass
                finally:
                    self.ui_update_queue.put(('progress', None, None))
                    task_queue.task_done()

        for _ in range(num_threads):
            threading.Thread(target=worker, daemon=True).start()

        task_queue.join()  # Wait for all tasks to be done
        self.ui_update_queue.put(('finished', "Scan finished.", None))

    # --- NEW: This function processes the UI update queue in batches ---
    def process_ui_updates(self):
        progress_updates = 0
        try:
            while not self.ui_update_queue.empty():
                update_type, data1, data2 = self.ui_update_queue.get_nowait()

                if update_type == 'result':
                    self.add_result(data1, data2)
                elif update_type == 'progress':
                    progress_updates += 1
                elif update_type == 'finished':
                    self.on_scan_complete(data1)
                    return
                elif update_type == 'error':
                    messagebox.showerror(data1, data2)
                    self.on_scan_complete("Error.")
                    return
        finally:
            if progress_updates > 0:
                self.update_progress(progress_updates)

        if self.is_scanning:
            self.after(100, self.process_ui_updates)

    def on_scan_complete(self, message):
        self.is_scanning = False
        self.start_btn.config(text="Start Scan")
        self.set_controls_state("normal")
        self.update_status(message)

    def add_result(self, status, url):
        with self.lock:
            self.found_count += 1

        if 200 <= status < 300:
            tag = 'status_2xx'
        elif 300 <= status < 400:
            tag = 'status_3xx'
        elif 400 <= status < 500:
            tag = 'status_4xx'
        elif 500 <= status < 600:
            tag = 'status_5xx'
        else:
            tag = 'status_other'

        self.results_tree.insert("", "end", values=(status, url), tags=(tag,))

    def update_status(self, message=None):
        if message:
            self.status_var.set(f"{message} | Found: {self.found_count}")
        elif self.is_scanning:
            self.status_var.set(f"Scanning: {self.processed_count}/{self.total_tasks} | Found: {self.found_count}")
        else:
            self.status_var.set(f"Ready | Found: {self.found_count}")

    def update_progress(self, count):
        with self.lock:
            self.processed_count += count
            progress = (self.processed_count / self.total_tasks) * 100 if self.total_tasks > 0 else 0
            self.progress_bar['value'] = progress
            self.update_status()

    def clear_results(self):
        self.results_tree.delete(*self.results_tree.get_children())
        self.found_count = 0
        self.processed_count = 0
        self.progress_bar['value'] = 0
        self.update_status("Ready")

    def export_results(self):
        if not self.results_tree.get_children():
            messagebox.showinfo("Export", "Nothing to export.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv")])
        if not filepath: return
        with open(filepath, "w", newline="", encoding='utf-8') as f:
            if filepath.endswith(".csv"):
                import csv
                writer = csv.writer(f)
                writer.writerow(["Status Code", "URL"])
                for child in self.results_tree.get_children():
                    writer.writerow(self.results_tree.item(child)['values'])
            else:
                for child in self.results_tree.get_children():
                    status, url = self.results_tree.item(child)['values']
                    f.write(f"[{status}] {url}\n")
        messagebox.showinfo("Export Successful", f"Results saved to {filepath}")

    def browse_wordlist(self):
        filepath = filedialog.askopenfilename(title="Select a Wordlist File",
                                              filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filepath: self.wordlist_var.set(filepath)

    def set_controls_state(self, state):
        for widget in [self.url_entry, self.wordlist_entry, self.browse_btn, self.threads_spinbox, self.clear_btn]:
            widget.config(state=state)

    def on_closing(self):
        if self.is_scanning: self.stop_scan()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()