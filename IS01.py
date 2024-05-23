# Import necessary libraries
import tkinter as tk
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import string
import secrets
from tkinter import ttk

# Database connection
conn = sqlite3.connect('C:/Users/15715/Desktop/IS Final project/Database/KilariDB.db')
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS Passwords (
                Website_Name VARCHAR(30),
                User_Name VARCHAR(30),
                Password VARCHAR(100)
            )''')

master_password = None

# Function to generate a random password
def generate_random_password():
    """Generate a random password with 15 characters."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(15))
    return password

# Function to derive a key from the master password using PBKDF2HMAC
def derive_key_from_master_password(master_password):
    """Derive a key from the master password using PBKDF2HMAC."""
    password_bytes = master_password.encode('utf-8')
    salt = os.urandom(16)
    iterations = 100000
    length = 32

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    derived_key = kdf.derive(password_bytes)
    return derived_key, salt

# Function to encrypt a password using AES in CFB mode
def encrypt_password(password, key, salt):
    """Encrypt a password using AES in CFB mode."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_password = iv + encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    return urlsafe_b64encode(encrypted_password), salt

# Function to decrypt a password
def decrypt_password(encrypted_password, key, salt):
    """Decrypt a password."""
    iv = encrypted_password[:16]
    encrypted_password = urlsafe_b64decode(encrypted_password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_password = decryptor.update(encrypted_password[16:]) + decryptor.finalize()
    return decrypted_password.decode('utf-8')

# Function to set the master password
def set_master_password():
    """Set the master password and transition to the login screen."""
    global master_password
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()

    if password == confirm_password:
        master_password = password
        instruction_label.config(text="Please enter your Master Password for login", fg="black")
        confirm_password_label.grid_forget()
        confirm_password_entry.grid_forget()
        set_password_button.grid_forget()
        login_button.grid(row=4, column=1, padx=10, pady=5)
        password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)
    else:
        instruction_label.config(text="Passwords do not match. Please try again.", fg="red")

# Function to toggle showing/hiding the master password
def toggle_show_master_password():
    """Toggle showing/hiding the master password in the entry widget."""
    current_state = password_entry.cget("show")
    new_state = "" if current_state else "*"
    password_entry.config(show=new_state)

# Function to open the password manager window
def open_password_manager():
    """Open the password manager window."""
    global master_password
    password_manager_window = tk.Tk()
    password_manager_window.title("Password Manager")
    password_manager_window.geometry("400x300")

    welcome_label = tk.Label(password_manager_window, text="Welcome to Password Manager", font=("Arial", 14), pady=20)
    welcome_label.pack()

    # Function to add a new password
    def add_password():
        derived_key, salt = derive_key_from_master_password(master_password)
        open_password_entry_window(derived_key, salt)

    # Function to view all passwords
    def view_passwords():
        c.execute("SELECT * FROM Passwords")
        rows = c.fetchall()

        view_passwords_window = tk.Toplevel(password_manager_window)
        view_passwords_window.title("View Passwords")

        tree = ttk.Treeview(view_passwords_window, columns=("Website", "Username", "Password"), show='headings')
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")

        for row in rows:
            tree.insert("", "end", values=row)

        tree.pack()

        view_passwords_window.mainloop()

    add_password_button = tk.Button(password_manager_window, text="Add Password", command=add_password)
    add_password_button.pack()
    instruction_label = tk.Label(password_manager_window, text=" User can add the Website ,Username, Password Details ", font=("Serif", 10), pady=10)
    instruction_label.pack()

    view_password_button = tk.Button(password_manager_window, text="View Passwords", command=view_passwords)
    view_password_button.pack()
    instruction_label = tk.Label(password_manager_window, text=" Website ,Username, Password Details are displayed ", font=("Serif", 10), pady=10)
    instruction_label.pack()

    password_manager_window.mainloop()

# Function to handle login
def login():
    """Handle login and transition to the password manager window."""
    global master_password
    entered_password = password_entry.get()

    if entered_password == master_password:
        instruction_label.config(text="Login successful!", fg="green")
        derived_key, salt = derive_key_from_master_password(master_password)
        window.destroy()
        open_password_manager()
    else:
        instruction_label.config(text="Incorrect password. Please try again.", fg="red")

# Function to add a password to the database
def add_to_database(website, username, password):
    """Add a password to the database."""
    c.execute("INSERT INTO Passwords (Website_Name, User_Name, Password) VALUES (?, ?, ?)", (website, username, password))
    conn.commit()

# Function to open the window for entering a new password
def open_password_entry_window(key, salt):
    """Open the window for entering a new password."""
    def add_passwords():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        encrypted_password, encrypted_salt = encrypt_password(password, key, salt)
        add_to_database(website, username, encrypted_password.decode('utf-8'))
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

    def generate_password():
        random_password = generate_random_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, random_password)

    def toggle_show_password():
        current_state = password_entry.cget("show")
        new_state = "" if current_state else "*"
        password_entry.config(show=new_state)

    password_entry_window = tk.Tk()
    password_entry_window.title("Add_Passwords")

    instruction_label = tk.Label(password_entry_window, text="Please enter your passwords", font=("Arial", 12), pady=10)
    instruction_label.pack()

    website_label = tk.Label(password_entry_window, text="Website:")
    website_label.pack()
    website_entry = tk.Entry(password_entry_window)
    website_entry.pack()
    instruction_label = tk.Label(password_entry_window, text="Please enter your Website Name", font=("Arial", 8), pady=10)
    instruction_label.pack()

    username_label = tk.Label(password_entry_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(password_entry_window)
    username_entry.pack()
    instruction_label = tk.Label(password_entry_window, text="Please enter your Username", font=("Arial", 8), pady=10)
    instruction_label.pack()

    password_label = tk.Label(password_entry_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(password_entry_window, show="*")
    password_entry.pack()
    instruction_label = tk.Label(password_entry_window, text="Please enter your password", font=("Arial", 8), pady=10)
    instruction_label.pack()

    generate_password_button = tk.Button(password_entry_window, text="Generate Password", command=generate_password)
    generate_password_button.pack()
    instruction_label = tk.Label(password_entry_window, text="Random password created", font=("Arial", 8), pady=10)
    instruction_label.pack()

    show_password_checkbox = tk.Checkbutton(password_entry_window, text="Show Password", command=toggle_show_password)
    show_password_checkbox.pack()

    add_password_button = tk.Button(password_entry_window, text="Submit", command=add_passwords)
    add_password_button.pack()

    password_entry_window.mainloop()

# Create the main window
window = tk.Tk()
window.title("Password Manager")
window.configure(bg="Grey")
window.resizable(False, False)

# Create the center frame for the main window
center_frame = tk.Frame(window, bg="#d3d3d3")
center_frame.grid(row=0, column=0, padx=10, pady=10)

# Create labels and entries for setting the master password
instruction_label = tk.Label(center_frame, text="Please set your Master Password", bg="#d3d3d3")
instruction_label.grid(row=0, column=0, padx=10, pady=5)

password_label = tk.Label(center_frame, text="Master Password", bg="#d3d3d3")
password_label.grid(row=1, column=0, padx=10, pady=5)
password_entry = tk.Entry(center_frame, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)

# Add a checkbox for toggling show/hide master password
show_password_checkbox = tk.Checkbutton(center_frame, text="Show Master Password", command=toggle_show_master_password)
show_password_checkbox.grid(row=1, column=2, padx=10, pady=5)

confirm_password_label = tk.Label(center_frame, text="Confirm Password", bg="#d3d3d3")
confirm_password_label.grid(row=2, column=0, padx=10, pady=5)
confirm_password_entry = tk.Entry(center_frame, show="*")
confirm_password_entry.grid(row=2, column=1, padx=10, pady=5)

set_password_button = tk.Button(center_frame, text="Set Master Password", command=set_master_password)
set_password_button.grid(row=3, column=1, padx=10, pady=5)

login_button = tk.Button(center_frame, text="Login", command=login)
login_button.grid(row=4, column=1, padx=10, pady=5)

# Start the main event loop
window.mainloop()

# Close the database connection when done
conn.close()
