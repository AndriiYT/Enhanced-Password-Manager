import os
import json
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from cryptography.fernet import Fernet
import platform
import base64
import random
import string
import time
import threading
import re
import gc
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError

class SecureHashManager:
    
    def __init__(self):
        # Argon2 settings
        self.ph = PasswordHasher(
            time_cost=5,        # Number of iterations, default: 3
            memory_cost=131072,  # Memory usage in KB, default: (65536 is 64MB)
            parallelism=1,      # Number of parallel threads, default: 2
            hash_len=32,        # Hash length in bytes, default: 32
            salt_len=16         # Salt length in bytes, default: 16
        )
        self.encoding = 'utf-8'
    
    def hash_password(self, password):
        try:
            if isinstance(password, str):
                password = password.encode(self.encoding)
            elif isinstance(password, bytes):
                password = password.decode(self.encoding)
            
            hashed = self.ph.hash(password)
            return hashed
        except HashingError as e:
            raise Exception(f"Password hashing failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Unexpected error during hashing: {str(e)}")
    
    def verify_password(self, password, hashed_password):
        try:
            if isinstance(password, str):
                password = password.encode(self.encoding)
            elif isinstance(password, bytes):
                password = password.decode(self.encoding)
            
            self.ph.verify(hashed_password, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            raise Exception(f"Password verification failed: {str(e)}")
    
    def needs_rehash(self, hashed_password):
        try:
            return self.ph.check_needs_rehash(hashed_password)
        except Exception:
            return True
    
    def generate_secure_identifier(self, hashed_password):
        import hashlib
        return hashlib.sha256(hashed_password.encode()).hexdigest()

class EnhancedSecurityManager:
    
    def __init__(self, config_path):
        self.config_path = config_path
        self.hash_manager = SecureHashManager()
        self.max_attempts = 5
        self.base_lockout = 60  # Base lockout time in seconds
        self.max_lockout = 3600  # Maximum lockout time (1 hour)
        
    def get_security_config(self):
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            return config
        except (FileNotFoundError, json.JSONDecodeError):
            return self._create_default_config()
    
    def _create_default_config(self):
        return {
            'master_pin': None,
            'identifier': None,
            'failed_attempts': 0,
            'lockout_until': 0,
            'last_successful_login': 0,
            'hash_version': '2.0',
            'security_level': 'high'
        }
    
    def save_security_config(self, config):
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            raise Exception(f"Failed to save security config: {str(e)}")
    
    def is_locked_out(self):
        config = self.get_security_config()
        current_time = time.time()
        lockout_until = config.get('lockout_until', 0)
        
        if lockout_until > current_time:
            remaining = int(lockout_until - current_time)
            return True, remaining
        return False, 0
    
    def calculate_lockout_duration(self, failed_attempts):
        if failed_attempts <= self.max_attempts:
            return 0
        
        multiplier = 2 ** (failed_attempts - self.max_attempts)
        duration = min(self.base_lockout * multiplier, self.max_lockout)
        return int(duration)
    
    def record_failed_attempt(self):
        config = self.get_security_config()
        config['failed_attempts'] = config.get('failed_attempts', 0) + 1
        
        lockout_duration = self.calculate_lockout_duration(config['failed_attempts'])
        if lockout_duration > 0:
            config['lockout_until'] = time.time() + lockout_duration
        
        self.save_security_config(config)
        return config['failed_attempts'], lockout_duration
    
    def record_successful_login(self):
        config = self.get_security_config()
        config['failed_attempts'] = 0
        config['lockout_until'] = 0
        config['last_successful_login'] = time.time()
        self.save_security_config(config)
    
    def create_master_pin(self, pin):
        if len(pin) < 8:
            raise ValueError("PIN must be at least 8 characters long")
        
        try:
            hashed_pin = self.hash_manager.hash_password(pin)
            identifier = self.hash_manager.generate_secure_identifier(hashed_pin)
            
            config = self._create_default_config()
            config.update({
                'master_pin': hashed_pin,
                'identifier': identifier,
                'hash_version': '2.0',
                'created_at': time.time()
            })
            
            self.save_security_config(config)
            return hashed_pin, identifier
            
        except Exception as e:
            raise Exception(f"Failed to create master PIN: {str(e)}")
    
    def verify_master_pin(self, pin):
        is_locked, remaining_time = self.is_locked_out()
        if is_locked:
            raise Exception(f"Account locked. Try again in {remaining_time} seconds.")
        
        config = self.get_security_config()
        stored_hash = config.get('master_pin')
        
        if not stored_hash:
            raise Exception("No master PIN configured")
        
        try:
            if self.hash_manager.verify_password(pin, stored_hash):
                if self.hash_manager.needs_rehash(stored_hash):
                    self._update_pin_hash(pin, config)
                
                self.record_successful_login()
                return stored_hash
            else:
                attempts, lockout_duration = self.record_failed_attempt()
                remaining_attempts = max(0, self.max_attempts - attempts)
                
                if lockout_duration > 0:
                    raise Exception(f"Too many failed attempts. Locked out for {lockout_duration} seconds.")
                else:
                    raise Exception(f"Incorrect PIN. {remaining_attempts} attempts remaining.")
                
        except Exception as e:
            if "Account locked" in str(e) or "Too many failed attempts" in str(e) or "Incorrect PIN" in str(e):
                raise
            else:
                self.record_failed_attempt()
                raise Exception("PIN verification failed")
    
    def _update_pin_hash(self, pin, config):
        try:
            new_hash = self.hash_manager.hash_password(pin)
            new_identifier = self.hash_manager.generate_secure_identifier(new_hash)
            
            config['master_pin'] = new_hash
            config['identifier'] = new_identifier
            config['hash_version'] = '2.0'
            config['updated_at'] = time.time()
            
            self.save_security_config(config)
        except Exception:
            pass

class SecureKeyManager:
    
    def __init__(self, key_path):
        self.key_path = key_path
        
    def generate_master_key(self):
        if not os.path.exists(self.key_path):
            master_key = secrets.token_bytes(32)
            
            os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
            
            with open(self.key_path, 'wb') as f:
                f.write(master_key)
        
        return self.load_master_key()
    
    def load_master_key(self):
        try:
            with open(self.key_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            raise Exception("Master key file not found")
    
    def derive_encryption_key(self, master_key, pin_hash):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        salt = pin_hash.encode()[:16].ljust(16, b'\x00')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        derived_key = kdf.derive(master_key)
        return base64.urlsafe_b64encode(derived_key)

class EnhancedPasswordManagerApp(tk.Tk):
    
    def __init__(self, security_manager, key_manager, data_path, directory):
        super().__init__()
        
        self.security_manager = security_manager
        self.key_manager = key_manager
        self.data_path = data_path
        self.directory = directory
        
        self.last_activity = time.time()
        self.auto_lock_minutes = 15
        self.session_active = True
        
        self._setup_window()
        self._initialize_data()
        self._setup_ui()
        self._start_security_monitoring()
        
    def _setup_window(self):
        self.title("Enhanced Password Manager")
        self.geometry("1200x800")
        
        if platform.system() == 'Windows':
            self.state('zoomed')
        else:
            self.attributes('-zoomed', True)
        
        if platform.system() == 'Windows':
            try:
                import ctypes
                from ctypes import wintypes
                hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
                ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000011)
            except:
                pass
    
    def _initialize_data(self):
        try:
            master_key = self.key_manager.generate_master_key()
            config = self.security_manager.get_security_config()
            pin_hash = config.get('master_pin', '')
            
            self.encryption_key = self.key_manager.derive_encryption_key(master_key, pin_hash)
            
            self.data = self._load_encrypted_data()
            self.filtered_data = self.data.copy()
            self.selected_index = None
            
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Failed to initialize: {str(e)}")
            self.destroy()
    
    def _load_encrypted_data(self):
        if not os.path.exists(self.data_path):
            return []
            
        try:
            with open(self.data_path, 'rb') as f:
                encrypted_data = f.read()
            
            fernet = Fernet(self.encryption_key)
            decrypted = fernet.decrypt(encrypted_data)
            data_dict = json.loads(decrypted.decode())
            
            return data_dict.get('entries', [])
            
        except Exception as e:
            messagebox.showerror("Data Error", f"Failed to load data: {str(e)}")
            return []
    
    def _save_encrypted_data(self):
        try:
            config = self.security_manager.get_security_config()
            data_dict = {
                'identifier': config.get('identifier', ''),
                'entries': self.data,
                'version': '2.0',
                'saved_at': time.time()
            }
            
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(json.dumps(data_dict).encode())
            
            os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
            
            temp_path = self.data_path + '.tmp'
            with open(temp_path, 'wb') as f:
                f.write(encrypted_data)
            
            if os.path.exists(self.data_path):
                backup_path = self.data_path + '.bak'
                os.rename(self.data_path, backup_path)
            
            os.rename(temp_path, self.data_path)
            
            if os.path.exists(backup_path):
                os.remove(backup_path)
                
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save data: {str(e)}")
    
    def _setup_ui(self):
        for i in range(4):
            self.columnconfigure(i, weight=1)
        self.rowconfigure(7, weight=1)
        
        tk.Label(self, text="Search Website/Source:", font=('Arial', 10, 'bold')).grid(
            row=0, column=0, sticky='e', padx=5, pady=5
        )
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self._update_listbox)
        search_entry = tk.Entry(self, textvariable=self.search_var, font=('Arial', 10))
        search_entry.grid(row=0, column=1, columnspan=3, sticky='we', padx=5, pady=5)
        
        self._setup_entry_fields()
        self._setup_action_buttons()
        self._setup_settings_section()
        self._setup_listbox()
        self._setup_copy_buttons()
        self._update_listbox()
        
        self.bind_all('<Button-1>', self._reset_activity_timer)
        self.bind_all('<Key>', self._reset_activity_timer)
    
    def _setup_entry_fields(self):
        self.name_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.website_var = tk.StringVar()
        
        tk.Label(self, text="Name:", font=('Arial', 10)).grid(row=1, column=0, sticky='e', padx=5, pady=2)
        tk.Entry(self, textvariable=self.name_var, font=('Arial', 10)).grid(
            row=1, column=1, sticky='we', padx=5, pady=2
        )
        
        tk.Label(self, text="Email:", font=('Arial', 10)).grid(row=2, column=0, sticky='e', padx=5, pady=2)
        tk.Entry(self, textvariable=self.email_var, font=('Arial', 10)).grid(
            row=2, column=1, sticky='we', padx=5, pady=2
        )
        
        tk.Label(self, text="Password:", font=('Arial', 10, 'bold')).grid(row=3, column=0, sticky='e', padx=5, pady=2)
        self.password_entry = tk.Entry(self, textvariable=self.password_var, show='*', font=('Arial', 10))
        self.password_entry.grid(row=3, column=1, sticky='we', padx=5, pady=2)
        self.password_entry.bind('<KeyRelease>', self._check_password_strength)
        
        self.strength_var = tk.StringVar()
        self.strength_label = tk.Label(self, textvariable=self.strength_var, font=('Arial', 9))
        self.strength_label.grid(row=3, column=2, columnspan=2, sticky='w', padx=5)
        
        tk.Label(self, text="Website/Source:", font=('Arial', 10, 'bold')).grid(row=4, column=0, sticky='e', padx=5, pady=2)
        tk.Entry(self, textvariable=self.website_var, font=('Arial', 10)).grid(
            row=4, column=1, sticky='we', padx=5, pady=2
        )
    
    def _setup_action_buttons(self):
        button_frame = tk.Frame(self)
        button_frame.grid(row=5, column=0, columnspan=4, pady=10)
        
        buttons = [
            ("Add Entry", self._add_entry, 'green'),
            ("Modify Entry", self._modify_entry, 'orange'),
            ("Delete Entry", self._delete_entry, 'red'),
            ("Generate Password", self._generate_password, 'blue'),
            ("Lock & Exit", self._lock_and_exit, 'gray')
        ]
        
        for i, (text, command, color) in enumerate(buttons):
            btn = tk.Button(button_frame, text=text, command=command, 
                          font=('Arial', 10, 'bold'), bg=color, fg='white')
            btn.grid(row=0, column=i, padx=5, sticky='ew')
            button_frame.columnconfigure(i, weight=1)
    
    def _setup_settings_section(self):
        settings_frame = tk.Frame(self)
        settings_frame.grid(row=6, column=0, columnspan=4, pady=5)
        
        tk.Label(settings_frame, text="Auto-lock (minutes):", font=('Arial', 9)).pack(side=tk.LEFT, padx=5)
        self.autolock_var = tk.StringVar(value=str(self.auto_lock_minutes))
        autolock_entry = tk.Entry(settings_frame, textvariable=self.autolock_var, width=5, font=('Arial', 9))
        autolock_entry.pack(side=tk.LEFT, padx=5)
        autolock_entry.bind('<KeyRelease>', self._update_autolock_setting)
        
        tk.Button(settings_frame, text="Export Data", command=self._export_data, 
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=10)
        tk.Button(settings_frame, text="Import Data", command=self._import_data, 
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=5)
        
        tk.Label(settings_frame, text=f"Entries: {len(self.data)}", 
                font=('Arial', 9), fg='blue').pack(side=tk.RIGHT, padx=5)
    
    def _setup_listbox(self):
        list_frame = tk.Frame(self)
        list_frame.grid(row=7, column=0, columnspan=4, sticky='nsew', padx=5, pady=5)
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        
        self.listbox = tk.Listbox(list_frame, font=('Arial', 10))
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar.set)
        
        self.listbox.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')
        
        self.listbox.bind('<<ListboxSelect>>', self._on_listbox_select)
    
    def _setup_copy_buttons(self):
        copy_frame = tk.Frame(self)
        copy_frame.grid(row=8, column=0, columnspan=4, pady=10)
        
        copy_buttons = [
            ("Copy Password", self._copy_password),
            ("Copy Email", self._copy_email),
            ("Copy Website", self._copy_website),
            ("Show Password", self._toggle_password_visibility)
        ]
        
        for i, (text, command) in enumerate(copy_buttons):
            btn = tk.Button(copy_frame, text=text, command=command, font=('Arial', 10))
            btn.grid(row=0, column=i, padx=5, sticky='ew')
            copy_frame.columnconfigure(i, weight=1)
    
    def _start_security_monitoring(self):
        def monitor_auto_lock():
            while self.session_active:
                time.sleep(30)
                if time.time() - self.last_activity > (self.auto_lock_minutes * 60):
                    self.after(0, self._auto_lock)
                    break
        
        self.auto_lock_thread = threading.Thread(target=monitor_auto_lock, daemon=True)
        self.auto_lock_thread.start()
    
    def _reset_activity_timer(self, event=None):
        self.last_activity = time.time()
    
    def _auto_lock(self):
        if self.session_active:
            messagebox.showinfo("Auto-Lock", 
                              f"Application locked after {self.auto_lock_minutes} minutes of inactivity.")
            self._lock_and_exit()
    
    def _update_autolock_setting(self, event=None):
        try:
            minutes = int(self.autolock_var.get())
            if 1 <= minutes <= 120:
                self.auto_lock_minutes = minutes
        except ValueError:
            pass
    
    def _check_password_strength(self, event=None):
        password = self.password_var.get()
        if not password:
            self.strength_var.set("")
            self.strength_label.config(fg='black')
            return
        
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Use 12+ characters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase")
            
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase")
            
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add symbols")
        
        if len(set(password)) > len(password) * 0.7:
            score += 1
        
        if score >= 6:
            strength, color = "Very Strong", 'green'
        elif score >= 5:
            strength, color = "Strong", 'darkgreen'
        elif score >= 3:
            strength, color = "Medium", 'orange'
        elif score >= 2:
            strength, color = "Weak", 'red'
        else:
            strength, color = "Very Weak", 'darkred'
        
        self.strength_var.set(f"Strength: {strength}")
        self.strength_label.config(fg=color)
    
    def _generate_password(self):
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        all_chars = lowercase + uppercase + digits + symbols
        for _ in range(12):
            password_chars.append(secrets.choice(all_chars))
        
        secrets.SystemRandom().shuffle(password_chars)
        
        password = ''.join(password_chars)
        self.password_var.set(password)
        self._check_password_strength()
        
        messagebox.showinfo("Password Generated", "Strong password generated successfully!")
    
    def _update_listbox(self, *args):
        search_term = self.search_var.get().lower()
        self.filtered_data = [
            entry for entry in self.data 
            if search_term in entry.get('website', '').lower() or 
               search_term in entry.get('email', '').lower() or
               search_term in entry.get('name', '').lower()
        ]
        
        self.listbox.delete(0, tk.END)
        for entry in self.filtered_data:
            display_text = f"{entry.get('website', 'Unknown')} - {entry.get('email', 'No email')}"
            if entry.get('name'):
                display_text = f"{entry['name']} ({display_text})"
            self.listbox.insert(tk.END, display_text)
        
        for widget in self.children.values():
            if isinstance(widget, tk.Frame):
                for child in widget.children.values():
                    if isinstance(child, tk.Label) and "Entries:" in str(child.cget('text')):
                        child.config(text=f"Entries: {len(self.data)} (Showing: {len(self.filtered_data)})")
        
        self._reset_activity_timer()
    
    def _add_entry(self):
        if not self._validate_entry():
            return
        
        website = self.website_var.get().strip()
        email = self.email_var.get().strip()
        
        for entry in self.data:
            if (entry.get('website', '').lower() == website.lower() and 
                entry.get('email', '').lower() == email.lower()):
                if not messagebox.askyesno("Duplicate Entry", 
                    "An entry with this website and email already exists. Add anyway?"):
                    return
                break
        
        new_entry = {
            'name': self.name_var.get().strip(),
            'email': email,
            'password': self.password_var.get(),
            'website': website,
            'created_at': time.time(),
            'modified_at': time.time()
        }
        
        self.data.append(new_entry)
        self._save_encrypted_data()
        self._clear_entry_fields()
        self._update_listbox()
        
        messagebox.showinfo("Success", "Entry added successfully!")
        self._reset_activity_timer()
    
    def _modify_entry(self):
        if self.selected_index is None:
            messagebox.showerror("Error", "Please select an entry to modify.")
            return
        
        if not self._validate_entry():
            return
        
        original_index = self.data.index(self.filtered_data[self.selected_index])
        self.data[original_index].update({
            'name': self.name_var.get().strip(),
            'email': self.email_var.get().strip(),
            'password': self.password_var.get(),
            'website': self.website_var.get().strip(),
            'modified_at': time.time()
        })
        
        self._save_encrypted_data()
        self._clear_entry_fields()
        self._update_listbox()
        
        messagebox.showinfo("Success", "Entry modified successfully!")
        self._reset_activity_timer()
    
    def _delete_entry(self):
        if self.selected_index is None:
            messagebox.showerror("Error", "Please select an entry to delete.")
            return
        
        entry = self.filtered_data[self.selected_index]
        website = entry.get('website', 'Unknown')
        
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete the entry for '{website}'?\n\nThis action cannot be undone."):
            original_index = self.data.index(entry)
            del self.data[original_index]
            
            self._save_encrypted_data()
            self._clear_entry_fields()
            self._update_listbox()
            
            messagebox.showinfo("Success", "Entry deleted successfully!")
        
        self._reset_activity_timer()
    
    def _validate_entry(self):
        password = self.password_var.get()
        website = self.website_var.get().strip()
        
        if not password:
            messagebox.showerror("Validation Error", "Password is required.")
            return False
        
        if not website:
            messagebox.showerror("Validation Error", "Website/Source is required.")
            return False
        
        if len(password) < 8:
            if not messagebox.askyesno("Weak Password", 
                "This password is very short (less than 8 characters).\n\nSave anyway?"):
                return False
        
        return True
    
    def _clear_entry_fields(self):
        self.name_var.set('')
        self.email_var.set('')
        self.password_var.set('')
        self.website_var.set('')
        self.strength_var.set('')
        self.selected_index = None
    
    def _on_listbox_select(self, event):
        if not self.listbox.curselection():
            return
        
        index = self.listbox.curselection()[0]
        self.selected_index = index
        
        if index < len(self.filtered_data):
            entry = self.filtered_data[index]
            self.name_var.set(entry.get('name', ''))
            self.email_var.set(entry.get('email', ''))
            self.password_var.set(entry.get('password', ''))
            self.website_var.set(entry.get('website', ''))
            self._check_password_strength()
        
        self._reset_activity_timer()
    
    def _copy_password(self):
        if self.selected_index is None:
            messagebox.showerror("Error", "Please select an entry first.")
            return
        
        password = self.filtered_data[self.selected_index].get('password', '')
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            self.update()
            messagebox.showinfo("Success", "Password copied to clipboard!")
            
            self.after(30000, self._clear_clipboard)
        else:
            messagebox.showwarning("Warning", "No password found for this entry.")
        
        self._reset_activity_timer()
    
    def _copy_email(self):
        if self.selected_index is None:
            messagebox.showerror("Error", "Please select an entry first.")
            return
        
        email = self.filtered_data[self.selected_index].get('email', '')
        if email:
            self.clipboard_clear()
            self.clipboard_append(email)
            self.update()
            messagebox.showinfo("Success", "Email copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No email found for this entry.")
        
        self._reset_activity_timer()
    
    def _copy_website(self):
        if self.selected_index is None:
            messagebox.showerror("Error", "Please select an entry first.")
            return
        
        website = self.filtered_data[self.selected_index].get('website', '')
        if website:
            self.clipboard_clear()
            self.clipboard_append(website)
            self.update()
            messagebox.showinfo("Success", "Website copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No website found for this entry.")
        
        self._reset_activity_timer()
    
    def _toggle_password_visibility(self):
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.after(10000, lambda: self.password_entry.config(show='*'))
        else:
            self.password_entry.config(show='*')
        
        self._reset_activity_timer()
    
    def _clear_clipboard(self):
        try:
            self.clipboard_clear()
            self.update()
        except:
            pass
    
    def _export_data(self):
        if not self.data:
            messagebox.showwarning("Warning", "No data to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Password Data"
        )
        
        if filename:
            try:
                export_data = {
                    'entries': self.data,
                    'export_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'version': '2.0',
                    'total_entries': len(self.data)
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Export Success", 
                                  f"Successfully exported {len(self.data)} entries to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
        
        self._reset_activity_timer()
    
    def _import_data(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Password Data"
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    import_data = json.load(f)
                
                if 'entries' not in import_data:
                    messagebox.showerror("Import Error", "Invalid file format. Missing 'entries' key.")
                    return
                
                entries_to_import = import_data['entries']
                if not isinstance(entries_to_import, list):
                    messagebox.showerror("Import Error", "Invalid data format.")
                    return
                
                choice = messagebox.askyesnocancel(
                    "Import Method",
                    f"Found {len(entries_to_import)} entries to import.\n\n"
                    "Yes: Merge with existing data\n"
                    "No: Replace all existing data\n"
                    "Cancel: Cancel import"
                )
                
                if choice is None:
                    return
                elif choice:
                    self.data.extend(entries_to_import)
                    action = "merged"
                else:
                    self.data = entries_to_import
                    action = "replaced"
                
                self._save_encrypted_data()
                self._update_listbox()
                
                messagebox.showinfo("Import Success", 
                                  f"Successfully {action} data. Total entries: {len(self.data)}")
                
            except json.JSONDecodeError:
                messagebox.showerror("Import Error", "Invalid JSON file format.")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import data: {str(e)}")
        
        self._reset_activity_timer()
    
    def _lock_and_exit(self):
        if messagebox.askyesno("Lock & Exit", "Lock the password manager and exit?"):
            self.session_active = False
            
            self._secure_cleanup()
            
            self.destroy()
    
    def _secure_cleanup(self):
        try:
            for var in [self.name_var, self.email_var, self.password_var, 
                       self.website_var, self.search_var, self.strength_var]:
                var.set('')
            
            self._clear_clipboard()
            
            if hasattr(self, 'data'):
                self.data.clear()
            if hasattr(self, 'filtered_data'):
                self.filtered_data.clear()
            
            gc.collect()
            
        except Exception:
            pass


def create_fake_files(directory, count=10):
    fake_extensions = ['.txt', '.log', '.tmp', '.bak', '.cfg']
    fake_names = ['temp', 'backup', 'config', 'log', 'data', 'cache', 'system']
    
    for _ in range(count):
        name = secrets.choice(fake_names) + str(secrets.randbelow(1000))
        ext = secrets.choice(fake_extensions)
        filename = name + ext
        
        try:
            filepath = os.path.join(directory, filename)
            with open(filepath, 'w') as f:
                fake_content = ''.join(secrets.choice(string.ascii_letters + string.digits + ' \n') 
                                     for _ in range(secrets.randbelow(500) + 100))
                f.write(fake_content)
        except Exception:
            pass


def setup_application():
    try:
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))

        data_dir = os.path.join(app_dir, '.pmdata')
        os.makedirs(data_dir, exist_ok=True)
        
        config_path = os.path.join(data_dir, 'security.json')
        data_path = os.path.join(data_dir, 'vault.dat')
        key_path = os.path.join(data_dir, 'master.key')
        
        create_fake_files(app_dir)
        
        security_manager = EnhancedSecurityManager(config_path)
        key_manager = SecureKeyManager(key_path)
        
        return security_manager, key_manager, data_path, data_dir
        
    except Exception as e:
        messagebox.showerror("Setup Error", f"Failed to setup application: {str(e)}")
        return None, None, None, None


def authenticate_user(security_manager):
    try:
        config = security_manager.get_security_config()
        
        if not config.get('master_pin'):
            messagebox.showinfo("Welcome", 
                              "Welcome to Enhanced Password Manager!\n\n"
                              "Please create a master PIN to secure your passwords.")
            
            while True:
                pin = simpledialog.askstring("Create Master PIN", 
                                           "Create a master PIN (minimum 8 characters):", 
                                           show='*')
                if not pin:
                    return None
                
                if len(pin) < 8:
                    messagebox.showerror("Error", "PIN must be at least 8 characters long.")
                    continue
                
                confirm_pin = simpledialog.askstring("Confirm Master PIN", 
                                                   "Confirm your master PIN:", 
                                                   show='*')
                if not confirm_pin:
                    return None
                
                if pin != confirm_pin:
                    messagebox.showerror("Error", "PINs do not match. Please try again.")
                    continue
                
                try:
                    hashed_pin, identifier = security_manager.create_master_pin(pin)
                    messagebox.showinfo("Success", "Master PIN created successfully!")
                    return hashed_pin
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to create master PIN: {str(e)}")
                    continue
        
        else:
            max_attempts = 5
            
            for attempt in range(max_attempts):
                try:
                    is_locked, remaining_time = security_manager.is_locked_out()
                    if is_locked:
                        messagebox.showerror("Account Locked", 
                                           f"Account is locked due to too many failed attempts.\n"
                                           f"Try again in {remaining_time} seconds.")
                        return None
                    
                    pin = simpledialog.askstring("Enter Master PIN", 
                                               f"Enter your master PIN (Attempt {attempt + 1}/{max_attempts}):", 
                                               show='*')
                    if not pin:
                        return None
                    
                    hashed_pin = security_manager.verify_master_pin(pin)
                    messagebox.showinfo("Success", "Authentication successful!")
                    return hashed_pin
                    
                except Exception as e:
                    error_msg = str(e)
                    messagebox.showerror("Authentication Failed", error_msg)
                    
                    if "Locked out" in error_msg or "Account locked" in error_msg:
                        return None
                    
                    remaining = max_attempts - attempt - 1
                    if remaining > 0:
                        messagebox.showinfo("Try Again", f"{remaining} attempts remaining.")
                    else:
                        messagebox.showerror("Access Denied", 
                                           "Maximum attempts exceeded. Application will exit.")
                        return None
        
    except Exception as e:
        messagebox.showerror("Authentication Error", f"Authentication failed: {str(e)}")
        return None


def main():
    try:
        root = tk.Tk()
        root.withdraw()
        
        security_manager, key_manager, data_path, data_dir = setup_application()
        if not security_manager:
            return
        
        hashed_pin = authenticate_user(security_manager)
        if not hashed_pin:
            return
        
        root.destroy()
        
        app = EnhancedPasswordManagerApp(security_manager, key_manager, data_path, data_dir)
        
        def on_closing():
            if messagebox.askokcancel("Quit", "Are you sure you want to quit and lock the password manager?"):
                app._secure_cleanup()
                app.destroy()
        
        app.protocol("WM_DELETE_WINDOW", on_closing)
        
        app.mainloop()
        
    except Exception as e:
        messagebox.showerror("Application Error", f"An unexpected error occurred: {str(e)}")
    
    finally:
        try:
            gc.collect()
        except:
            pass


if __name__ == "__main__":
    import sys
    main()