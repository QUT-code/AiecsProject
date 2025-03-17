import tkinter as tk
from datetime import datetime

# Function to get the current date and time in a specific format
def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Send a message from one sender to the other
def send_message(sender_entry, sender_chat_window, receiver_chat_window, sender_name, alignment):
    message = sender_entry.get()
    if message:
        # Display the message in the sender's chat window
        display_message(f"{sender_name}: {message}", sender_chat_window, alignment)
        # Simulate sending the message to the receiver (display message in receiver's chat window)
        display_message(f"{sender_name}: {message}", receiver_chat_window, "right" if alignment == "left" else "left")

        # After a short delay, display 'Seen by at' in the receiver's chat window
        receiver_chat_window.after(1000, lambda: display_message(f"Seen by at {get_current_time()}", receiver_chat_window, "right" if alignment == "left" else "left"))

        # Clear the text input field after sending the message
        sender_entry.delete(0, tk.END)

# Display and update the message in the chat window with specific alignment
def display_message(message, chat_window, alignment):
    chat_window.config(state=tk.NORMAL)
    if alignment == 'left':
        chat_window.insert(tk.END, message + "\n")
    else:
        # Right-align the message
        chat_window.insert(tk.END, message + "\n")
    chat_window.config(state=tk.DISABLED)
    chat_window.yview(tk.END)
