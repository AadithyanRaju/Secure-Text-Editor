# Secure Text Editor with AES Encryption

This project is a simple **Secure Text Editor** designed for writing and storing encrypted text files. It uses **AES encryption** with user-defined keys and iterations to ensure the privacy of your files. The editor integrates encryption and decryption mechanisms, providing a secure way to save and open encrypted files.

## Features
- AES encryption with user-defined keys (`k1`, `k2`) and iterations (`a`, `b`).
- Password-based key derivation using PBKDF2 with a salt.
- HMAC validation to ensure file integrity.
- Secure encryption and decryption operations.
- Dark theme for the text editor.
- Status bar to show file save and open status.
- Built using **PyQt5** for the graphical user interface.

## Installation

To run this project, you need to have Python and the required dependencies installed. Follow the steps below to set up and run the project.

### Prerequisites
- Python 3.x
- PyQt5
- pycryptodome
- hashlib
- hmac

### Install Dependencies
You can install the required dependencies using **pip**:

```bash
pip install pyqt5 pycryptodome
```

## Usage

1. **Run the Application**:
   After installation, simply run the application using 
   ```bash
   python secret_diary.py
   ```

2. **New File**:
   - Click on **File > New** to create a new, empty file.
   - The editor will ask you for two encryption keys (`k1`, `k2`) and the number of iterations (`a`, `b`).

3. **Save File**:
   - Once you've written some text in the editor, click **File > Save**.
   - The editor will ask for encryption parameters if the file is being saved for the first time.
   - The file will be saved in an encrypted format with `.enc` extension.

4. **Open File**:
   - To open an encrypted file, click **File > Open**.
   - The editor will ask for encryption parameters and verify the file’s integrity using HMAC.
   - If the file is valid, it will be decrypted and opened.

5. **File Integrity**:
   - The application uses **HMAC** to verify that the file has not been tampered with.
   - If the integrity check fails, the user will be alerted, and the file will not be opened.

6. **Encryption and Decryption**:
   - The application uses **AES (Advanced Encryption Standard)** in CBC mode for encrypting and decrypting text.
   - PBKDF2 key derivation function is used to derive encryption keys from the user's password.

## Security
- Keys (`k1`, `k2`) and the number of iterations (`a`, `b`) are securely handled during the encryption/decryption process.
- After use, keys are zeroed out and deleted to ensure they are not stored in memory.
- A **status bar** shows the current state, such as "Saving file..." or "File saved successfully."

## Example of Usage:

1. **Create a New File**:
   - Start by clicking on **File > New** to create a new, empty file in the editor.

2. **Enter Encryption Keys**:
   - When prompted, input two encryption keys (`k1`, `k2`) and the number of iterations (`a`, `b`) you wish to use for encrypting the file.

3. **Write Your Text File**:
   - Write your text in the editor.

4. **Save the File**:
   - Once you're done writing, click **File > Save**. The editor will prompt you to enter encryption parameters if it's the first time saving the file.
   - The text will be encrypted and saved with a `.enc` extension.

5. **Open the Encrypted File**:
   - To open an encrypted file, click **File > Open**.
   - You will need to input the correct encryption keys (`k1`, `k2`) and iterations (`a`, `b`) to decrypt the file.
   - Once decrypted, the content will appear in the editor for you to read and edit.

6. **Ensure File Integrity**:
   - During the opening process, the application will verify the file's integrity using **HMAC** to ensure it hasn't been tampered with.
   - If the integrity check fails, you will receive an alert, and the file will not be opened.

7. **Modify and Re-save**:
   - You can modify the decrypted file and save it again, which will encrypt the changes and store them securely.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements
- **PyQt5**: For building the GUI.
- **pycryptodome**: For the cryptographic operations (AES encryption, PBKDF2, etc.).
- **HMAC**: For ensuring file integrity.
- **Python**: For the core programming language that powers the application.

## Contributing

Feel free to fork this repository, open issues, or submit pull requests. Contributions are welcome! If you have any suggestions, improvements, or bug fixes, please create a pull request or open an issue to discuss.

1. Fork the repository.
2. Create a new branch for your changes.
3. Commit your changes.
4. Push your changes to your forked repository.
5. Create a pull request from your branch to the main repository.

If you're submitting a bug fix, please ensure to provide detailed information about the bug and how you resolved it. If you're submitting a new feature or improvement, please include tests where applicable.

Thank you for your contributions!
