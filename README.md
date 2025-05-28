# Universal File Encrypter

A robust, user-friendly file encryption tool built in Rust with a graphical user interface (GUI) using `egui`. This tool allows users to encrypt any file into a custom `.encr` format and decrypt it back, with added security features like decryption attempt tracking and an optional PDF disguise mode.

## Features

*   **Strong Encryption:** Uses AES-256-GCM for authenticated encryption, ensuring both confidentiality and integrity of your files.
*   **Secure Key Derivation:** Employs Argon2id, a modern key derivation function, to protect user passwords against brute-force and dictionary attacks. Each file encryption uses a unique salt.
*   **Decryption Attempt Limit:**
    *   Tracks the number of incorrect password attempts for each encrypted file.
    *   If the wrong key is entered more than three (3) times, the file's metadata (specifically the salt needed for key derivation) is intentionally corrupted, rendering the file permanently unrecoverable even with the correct password. This acts as a safeguard against prolonged brute-force attempts on a single file.
*   **Custom Encrypted Format (`.encr`):** Encrypted files are saved with a `.encr` extension.
*   **Disguise Mode (Optional PDF):**
    *   Encrypted files can optionally be disguised as `.pdf` files.
    *   When opened with a standard PDF viewer, these disguised files will display custom, user-provided text.
    *   However, the embedded encrypted data remains recoverable by this tool when the correct password is provided.
*   **Intuitive GUI:** Built with `egui` for a cross-platform graphical interface, making it easy to select files, enter passwords, and choose options.
*   **Cross-Platform:** As a Rust application, it can be compiled for Windows, macOS, and Linux.

## Project Structure

The project is organized into several Rust modules for clarity and maintainability:
```
file_encrypter/
├── Cargo.toml # Manages project dependencies and build settings
├── README.md # This file
├── .gitignore # Specifies intentionally untracked files for Git
└── src/
├── main.rs # Entry point; GUI logic using egui and eframe
├── crypto.rs # Core cryptographic operations: encryption, decryption, key derivation (Argon2id, AES-256-GCM)
├── file_format.rs # Defines the structure of the custom .encr files, including metadata (salt, nonce, attempt counter, etc.) and PDF disguise markers.
├── pdf_handler.rs # Logic for creating and parsing disguised PDF files, embedding/extracting encrypted data.
└── error.rs # Custom error types for the application, facilitating robust error handling.
```
### Module Details:

*   **`main.rs`**:
    *   Initializes the `eframe` application and the main `FileEncrypterApp` struct.
    *   Handles the UI layout, widget interactions, and state management for the GUI.
    *   Spawns separate threads for cryptographic operations to keep the GUI responsive.
    *   Uses `mpsc` channels for communication between the UI thread and worker threads.
*   **`crypto.rs`**:
    *   `encrypt_file()`: Takes an input file, password, and options; produces an encrypted file (`.encr` or disguised PDF).
    *   `decrypt_file()`: Takes an encrypted file and password; attempts decryption, updates attempt counters, and handles file corruption on max attempts.
    *   `derive_key()`: Implements Argon2id key derivation.
    *   `hash_key_for_verification()`: Creates a hash of the derived key for password verification without full decryption.
*   **`file_format.rs`**:
    *   `FileMetadata` struct: Defines the metadata stored alongside encrypted data (salt, nonce, key verification hash, decryption attempts, original file extension).
    *   Constants for `MAX_DECRYPTION_ATTEMPTS`, file extensions, and PDF embedding markers.
*   **`pdf_handler.rs`**:
    *   `create_disguised_pdf()`: Generates a basic PDF document with user-provided text and appends the encrypted data payload (metadata + ciphertext) between special markers.
    *   `extract_data_from_pdf()`: Reads a PDF, searches for the embedded data markers, and extracts the encrypted payload.
*   **`error.rs`**:
    *   `EncryptError` enum: Custom error type aggregating potential errors from I/O, cryptography, serialization, PDF handling, and application logic.
    *   `Result<T>` type alias: `std::result::Result<T, EncryptError>`.

## Usage

1.  **Prerequisites:**
    *   Ensure you have Rust installed (see [rustup.rs](https://rustup.rs/)).
2.  **Build the Project:**
    *   Clone the repository or download the source code.
    *   Navigate to the project's root directory (`file_encrypter/`) in your terminal.
    *   Run `cargo build` for a debug build or `cargo build --release` for an optimized release build.
3.  **Run the Application:**
    *   After a successful build, the executable will be located in `target/debug/file_encrypter` or `target/release/file_encrypter`.
    *   Run the executable to launch the GUI.

### GUI Guide:

*   **Mode Selection:** Choose between "Encrypt" and "Decrypt" mode using the toggle buttons at the top.
*   **Input File:**
    *   Click "Browse..." or the path display area to select the file you want to encrypt or decrypt.
    *   The "❌" button clears the selection.
*   **Output:**
    *   **Output In:** Displays the directory where the output file will be saved (defaults to the input file's directory). Click "Change..." to select a different directory.
    *   **Output Name:** Enter the desired name for the output file (without the extension). The application will automatically suggest a name and append the correct extension (`.encr`, `.pdf`, or the original extension upon decryption).
*   **Password:**
    *   Enter a strong password for encryption or the correct password for decryption.
    *   **Confirm (Encrypt Mode):** Re-enter the password to ensure accuracy.
*   **Disguise as PDF (Encrypt Mode Only):**
    *   Check this box to embed the encrypted data within a PDF file.
    *   **PDF Display Text:** If disguising, enter the text you want to be visible when this PDF is opened by a standard PDF viewer. The text will be auto-wrapped in the generated PDF.
*   **Action Button:**
    *   Click "Encrypt File" or "Decrypt File" to perform the operation. The button is enabled only when all necessary fields are valid.
*   **Status Area:** Displays messages about the ongoing operation, success, or any errors encountered.

## Security Considerations

*   **Password Strength:** The security of your encrypted files heavily depends on the strength of your chosen password. Use long, complex, and unique passwords.
*   **Argon2 Parameters:** The application uses robust default parameters for Argon2id. These provide good resistance against current cracking techniques.
*   **Attempt Limit:** The 3-attempt limit before file corruption is a destructive measure. **Ensure you remember your password, as there is no recovery mechanism after the file is corrupted.**
*   **PDF Disguise:** The PDF disguise mode is for casual obfuscation, not high-level steganography. The embedded data can be found by someone specifically looking for it. Its primary purpose is to make the encrypted file less conspicuous.
*   **Physical Security:** Protect the device where passwords are typed and where encrypted/decrypted files are stored.

## Compatibility

*   **Operating Systems:** The application is built with Rust and `egui`, which are designed to be cross-platform. It should compile and run on:
    *   Windows
    *   macOS
    *   Linux
*   **File Types:** The tool can encrypt and decrypt *any* type of file. The original file type is preserved (via metadata) upon successful decryption.

## Dependencies

The project relies on several high-quality Rust crates:

*   `eframe` & `egui`: For the graphical user interface.
*   `rfd` (Rust File Dialogs): For native file open/save dialogs.
*   `aes-gcm`: For AES-256-GCM authenticated encryption.
*   `argon2`: For Argon2id password hashing and key derivation.
*   `rand`: For generating cryptographic random numbers (salts, nonces).
*   `sha2`: For hashing the derived key for verification.
*   `serde` & `bincode`: For serializing and deserializing file metadata.
*   `printpdf`: For generating the basic PDF structure in disguise mode.

(See `Cargo.toml` for specific versions.)

## Future Enhancements (Potential)

*   Stream processing for very large files to reduce memory usage.
*   More advanced steganography for PDF disguise.
*   Command-line interface (CLI) version.