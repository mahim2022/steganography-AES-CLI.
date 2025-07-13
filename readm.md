Steganography Encryption Tool

This is a Python-based tool that lets you securely hide encrypted messages inside image files (PNG/BMP) using AES-256 encryption and Least Significant Bit (LSB) steganography.  
It includes both a Command-Line Interface (CLI) and an easy-to-use Graphical User Interface (GUI) built with Tkinter.

---

 🚀 Features

- 🔒 AES-256 encryption with password protection (via PBKDF2)
- 🖼️ LSB-based steganography: hides message bits in pixel color channels
- 🧾 Command-line and GUI support
- 🎯 Lightweight, offline, cross-platform
- 🧪 Fully tested with `pytest`

---

 📦 Requirements

- Python 3.8+
- Poetry (for dependency management)

Install dependencies:

```bash
poetry install
⚙️ CLI Usage
Run the CLI:

bash
Copy
Edit
poetry run python cli.py --help
➕ Hide a Message
bash
Copy
Edit
poetry run python cli.py hide \
  --image original.png \
  --out stego.png \
  --password mySecret \
  --message "This is a hidden message"
You’ll be prompted to confirm your password.

🔍 Extract a Message
bash
Copy
Edit
poetry run python cli.py extract --image stego.png
You’ll be prompted for the decryption password.

🖼️ GUI Usage
Launch the GUI with:

bash
Copy
Edit
poetry run python gui.py
The GUI includes:

Tab 1: Hide Message

Select input image

Enter message and password

Save stego image

Tab 2: Extract Message

Select stego image

Enter password

View extracted message

🧪 Running Tests
To verify all functionality works correctly:

bash
Copy
Edit
poetry run pytest
📁 Project Structure
bash
Copy
Edit
hide_and_seek/
├── stego/
│   ├── crypto.py        # AES encryption/decryption
│   ├── embedder.py      # LSB embed logic
│   ├── extractor.py     # LSB extract logic
├── cli.py               # CLI interface (click)
├── gui.py               # Tkinter GUI
├── tests/               # pytest test cases
├── pyproject.toml       # Poetry config
└── README.md            # You're here
🛡️ Security Notes
Uses PBKDF2 with SHA256 to derive secure keys from passwords.

AES is run in CBC mode with random IVs per message.

The message length is stored in the image to ensure exact extraction.
