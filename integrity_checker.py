"""
Project Aegis: Self-Healing Integrity Guard
Author: Aditya (ACPCE Engineering)
Version: 1.0.0
Description: A HIDS (Host-based Intrusion Detection System) that uses 
             SHA-256 hashing to detect unauthorized file changes and 
             automatically restores them from a secure backup vault.
"""
import hashlib
import os
import json
import time
import sys
import shutil
import pathlib
from datetime import datetime

# --- CONFIGURATION ---
WATCH_FOLDER = "/home/aditya/Desktop/integrity_project/files_to_watch"
BACKUP_FOLDER = "/home/aditya/Desktop/integrity_project/backups"
BASELINE_PATH = "/home/aditya/Desktop/integrity_project/baseline.json"
LOG_FILE = "/home/aditya/Desktop/integrity_project/security_log.txt"
AUTH_USER = "aditya"  # The only user allowed to make changes

# Global dictionary to track the state in memory
active_baseline = {}

def log_event(message):
    """Logs the event with a timestamp and prints to console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")
    print(log_entry)

def calculate_hash(filepath):
    """Generates SHA-256 hash for a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def get_file_owner(filepath):
    """Returns the username of the file owner."""
    try:
        return pathlib.Path(filepath).owner()
    except Exception:
        return "Unknown"

def run_scan():
    global active_baseline
    watch_folder = "/home/aditya/Desktop/integrity_project/files_to_watch"
    backup_folder = "/home/aditya/Desktop/integrity_project/backups"
    authorized_user = "aditya" 

    if not os.path.exists(watch_folder):
        return

    current_files = os.listdir(watch_folder)
    
    # 1. Check for modifications and new files
    for filename in current_files:
        path = os.path.join(watch_folder, filename)
        curr_hash = calculate_hash(path)
        
        # Identify the current owner of the file
        try:
            current_owner = pathlib.Path(path).owner()
        except:
            current_owner = "unknown"

        if filename in active_baseline:
            if curr_hash != active_baseline[filename]:
                
                # --- CONDITION 1: Authorized User (aditya) ---
                if current_owner == authorized_user:
                    log_event(f"[*] Authorized modification to {filename} by {authorized_user}. Logged.")
                    active_baseline[filename] = curr_hash # Update baseline so it doesn't alert again
                
                # --- CONDITION 2: Unauthorized User (anyone else) ---
                else:
                    log_event(f"!!! CRITICAL: {filename} modified by {current_owner}. REVERTING...")
                    try:
                        # Recovery Step
                        if os.path.exists(path):
                            os.remove(path)
                        shutil.copy(os.path.join(backup_folder, filename), path)
                        log_event(f"[SUCCESS] {filename} has been self-healed.")
                    except Exception as e:
                        log_event(f"[ERROR] Restoration failed: {e}")
        
        else:
            # Handle brand new files
            if current_owner != authorized_user:
                log_event(f"!!! CRITICAL: Unauthorized new file {filename} by {current_owner}. DELETING...")
                os.remove(path)
            else:
                log_event(f"[*] New file {filename} created by {authorized_user}.")
                active_baseline[filename] = curr_hash

    # 2. Check for deletions
    for old_file in list(active_baseline.keys()):
        if old_file not in current_files:
            log_event(f"!!! ALERT: {old_file} was DELETED. RESTORING...")
            try:
                shutil.copy(os.path.join(BACKUP_FOLDER, old_file), os.path.join(WATCH_FOLDER, old_file))
            except Exception as e:
                log_event(f"[ERROR] Failed to restore deleted file: {e}")

def load_baseline():
    """Loads baseline from disk to memory."""
    global active_baseline
    if os.path.exists(BASELINE_PATH):
        with open(BASELINE_PATH, "r") as f:
            active_baseline = json.load(f)
        return True
    return False

if __name__ == "__main__":
    if "--shutdown-scan" in sys.argv:
        if load_baseline():
            log_event("[SYSTEM] Shutdown Scan Initiated.")
            run_scan()
            log_event("[SYSTEM] Final check complete.")
            
    elif "--monitor" in sys.argv:
        if load_baseline():
            log_event("[SYSTEM] Boot-up: Background Guard ACTIVE.")
            while True:
                run_scan()
                time.sleep(5)
        else:
            log_event("[-] Error: Service failed. Run Option 1 to create baseline first.")

    else:
        print("\n--- Self-Healing Integrity Guard ---")
        print("1. Initialize Baseline & Backups (Run this first!)")
        print("2. Manual Scan")
        choice = input("Select: ")
        
        if choice == "1":
            # Create backup folder if missing
            if not os.path.exists(BACKUP_FOLDER):
                os.makedirs(BACKUP_FOLDER)
                
            new_baseline = {}
            for f in os.listdir(WATCH_FOLDER):
                src = os.path.join(WATCH_FOLDER, f)
                dst = os.path.join(BACKUP_FOLDER, f)
                if os.path.isfile(src):
                    # Save Hash
                    new_baseline[f] = calculate_hash(src)
                    # Create "Known-Good" Backup
                    shutil.copy(src, dst)
            
            with open(BASELINE_PATH, "w") as db:
                json.dump(new_baseline, db)
            log_event(f"[+] Baseline & Backups created for {len(new_baseline)} files.")
