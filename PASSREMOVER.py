import os
import pikepdf
import logging
import coloredlogs
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import webbrowser
import ttkbootstrap as ttkb


# Setup logging
script_name = os.path.basename(__file__)
logging.basicConfig(level=logging.DEBUG, filename=script_name + ".log", filemode="a", encoding='utf-8',
                    format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG, logger=logger, fmt='[%(asctime)s] [%(levelname)s] %(message)s')

selected_files = []


# --- Utility Functions ---
def is_pdf_file(file_path):
    return file_path.lower().endswith('.pdf')


def validate_file_path(file_path):
    if not is_pdf_file(file_path):
        show_error("Please select a valid PDF file.")
        return False
    if not os.path.exists(file_path):
        show_error("File does not exist.")
        return False
    return True


def show_error(message):
    messagebox.showerror("Error", message)


# --- File Browsers ---
def browse_file():
    global selected_files
    open_file_button.config(state=tk.DISABLED)
    open_folder_button.config(state=tk.DISABLED)
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if file_path:
        selected_files = [file_path]
        file_path_entry.config(state=tk.NORMAL)
        file_path_entry.delete(0, tk.END)
        file_path_entry.insert(0, file_path)
        file_path_entry.config(state=tk.DISABLED)


def browse_files():
    global selected_files
    open_file_button.config(state=tk.DISABLED)
    open_folder_button.config(state=tk.DISABLED)
    files = filedialog.askopenfilenames(filetypes=[("PDF files", "*.pdf")])
    if files:
        selected_files = list(files)
        file_path_entry.config(state=tk.NORMAL)
        file_path_entry.delete(0, tk.END)
        file_path_entry.insert(0, "; ".join(selected_files))
        file_path_entry.config(state=tk.DISABLED)


# --- PDF Actions ---
def remove_pdf_password_bulk():
    file_password = password_entry.get()
    if not selected_files:
        show_error("No files selected. Please select PDF files first.")
        return

    for file_path in selected_files:
        if not validate_file_path(file_path):
            continue
        try:
            with pikepdf.open(file_path, password=file_password, allow_overwriting_input=True) as pdf_document:
                pdf_document.save(file_path, encryption=None)
                logger.info(f"Unlocked and replaced: {file_path}")
        except pikepdf.PasswordError:
            logger.error(f"Incorrect password for {file_path}")
            show_error(f"Incorrect password for {file_path}")
        except Exception as e:
            logger.error(f"Error unlocking {file_path}: {e}")
            show_error(f"Error unlocking {file_path}: {e}")

    messagebox.showinfo("Done", "Bulk unlock finished. Files replaced.")



def protect_pdf_bulk():
    new_password = new_password_entry.get()
    if not selected_files:
        show_error("No files selected. Please select PDF files first.")
        return
    if not new_password:
        show_error("Please enter a password to protect the PDFs.")
        return

    for file_path in selected_files:
        if not validate_file_path(file_path):
            continue
        try:
            with pikepdf.open(file_path, allow_overwriting_input=True) as pdf_document:
                pdf_document.save(
                    file_path,
                    encryption=pikepdf.Encryption(
                        user=new_password,
                        owner=new_password,
                        R=6  # AES-256
                    )
                )
                logger.info(f"Protected and replaced: {file_path}")
        except Exception as e:
            logger.error(f"Error protecting {file_path}: {e}")
            show_error(f"Error protecting {file_path}: {e}")

    messagebox.showinfo("Done", "Bulk protection finished. Files replaced.")


# --- Extras ---
def open_about():
    about_message = "PDF Password Manager\nCreated by Rama"
    messagebox.showinfo("About", about_message)


def open_github():
    webbrowser.open("")


# --- UI Setup ---
root = tk.Tk()
root.title("PDF Password Manager")
root.iconbitmap('icon.ico')
root.resizable(False, False)

style = ttkb.Style()
style.theme_use("darkly")
style.configure('TLabel', font=('Helvetica', 12))
style.configure('TButton', font=('Helvetica', 12))

ttk.Label(root, text="PDF Password Manager", font=('Helvetica', 16, 'bold')).pack(pady=20)

ttk.Label(root, text="PDF File(s):").pack(pady=5)
file_path_entry = ttk.Entry(root, width=60)
file_path_entry.pack(pady=5)
file_path_entry.config(state=tk.DISABLED)

ttk.Button(root, text="Browse Single", command=browse_file).pack(pady=5)
ttk.Button(root, text="Browse Multiple", command=browse_files).pack(pady=5)

ttk.Label(root, text="Password (for unlocking):").pack(pady=5)
password_entry = ttk.Entry(root, show="*", width=60)
password_entry.pack(pady=5)

ttk.Button(root, text="Unlock (Bulk, Replace)", command=remove_pdf_password_bulk).pack(pady=10)

ttk.Label(root, text="New Password (for protection):").pack(pady=5)
new_password_entry = ttk.Entry(root, show="*", width=60)
new_password_entry.pack(pady=5)

ttk.Button(root, text="Protect (Bulk, Replace)", command=protect_pdf_bulk).pack(pady=10)

ttk.Button(root, text="About", command=open_about).pack(side=tk.LEFT, padx=10, pady=10)

open_file_button = ttk.Button(root, text="(N/A in Replace Mode)")
open_file_button.pack(side=tk.LEFT, padx=10, pady=10)

open_folder_button = ttk.Button(root, text="(N/A in Replace Mode)")
open_folder_button.pack(side=tk.LEFT, padx=10, pady=10)

root.mainloop()
