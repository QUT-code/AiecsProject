import tkinter as tk
from tkinter import messagebox
import sqlite3
import bcrypt
import subprocess

# Database setup
def init_db():
    conn = sqlite3.connect('database/chat_app.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )
    ''')
    conn.commit()
    return conn

# Hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify password
def verify_password(stored_hash, password):
    stored_hash_bytes = stored_hash.encode()  # Convert string to bytes
    return bcrypt.checkpw(password.encode(), stored_hash_bytes)

# Create account
def create_account():
    username = entry_username.get()
    password = entry_password.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and password are required!")
        return

    password_hash = hash_password(password)

    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash.decode()))  # Decode bytes to string
        conn.commit()
        messagebox.showinfo("Success", "Account created successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")

# Login
def login():
    username = entry_username.get()
    password = entry_password.get()

    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result and verify_password(result[0], password):
        messagebox.showinfo("Success", "Login successful!")
        root.destroy()  # Close the login window
        subprocess.run(["python3", "ChatInterface.py", username])  # Open chat interface
    else:
        messagebox.showerror("Error", "Invalid username or password!")

# Forgot password
def forgot_password():
    username = entry_username.get()

    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result:
        new_password = "temp_password"  # In a real app, generate a secure temporary password
        new_hash = hash_password(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_hash.decode(), username))  # Decode bytes to string
        conn.commit()
        messagebox.showinfo("Success", f"Your password has been reset to: {new_password}")
    else:
        messagebox.showerror("Error", "Username not found!")

# GUI Setup
root = tk.Tk()
root.title("Messenger Login")
root.resizable(False, False)  # Prevent resizing

# Frame for organizing widgets
frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

# Username
label_username = tk.Label(frame, text="Username:")
label_username.grid(row=0, column=0, sticky="w")
entry_username = tk.Entry(frame, width=30)
entry_username.grid(row=0, column=1, pady=5)

# Password
label_password = tk.Label(frame, text="Password:")
label_password.grid(row=1, column=0, sticky="w")
entry_password = tk.Entry(frame, width=30, show="*")
entry_password.grid(row=1, column=1, pady=5)

# Buttons
button_create = tk.Button(frame, text="Create Account", command=create_account, width=15)
button_create.grid(row=2, column=0, pady=10)

button_login = tk.Button(frame, text="Login", command=login, width=15)
button_login.grid(row=2, column=1, pady=10)

button_forgot = tk.Button(frame, text="Forgot Password", command=forgot_password, width=15)
button_forgot.grid(row=3, column=0, columnspan=2, pady=10)

# Initialize database
conn = init_db()
cursor = conn.cursor()

root.mainloop()
