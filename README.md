# 🔐 Enhanced Password Manager (Python)

> A secure, local-first, offline password manager built with Argon2, PBKDF2, and Fernet encryption. No telemetry, no sync, full transparency.

![Preview](https://github.com/AndriiYT/Enhanced-Password-Manager/blob/main/password-manager.png)

---

## ✨ Features

- 🔒 Master PIN secured by **Argon2** hashing
- 🧠 Password strength scoring & generator
- 📁 Local-only storage with AES encryption (via **Fernet**)
- 🧼 Clipboard auto-clear + auto-lock after inactivity
- 🧱 Tamper detection
- 📊 Export/import entries (with merge or overwrite modes)
- 💻 GUI was made using `tkinter`, cross-platform support

---

## 🔧 Requirements

- Python 3.9+
- `cryptography`
- `argon2-cffi`

```bash
pip install cryptography argon2-cffi
```

---

## 📬 Contact

Questions, feedback, or requests for reuse/publication?  
Join my Discord: [discord.gg/jjkU7FWzht](https://discord.gg/jjkU7FWzht)

---

## ⚠️ Notice

I am trying to fix continuous fake file generation, but I can't.  
To disable it, comment out the line 932: `# create_fake_files(app_dir)`

And it'll stop!
