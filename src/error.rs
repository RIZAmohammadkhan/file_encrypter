use std::fmt;

#[derive(Debug)]
pub enum EncryptError {
    Io(std::io::Error),
    Crypto(aes_gcm::Error), // aes-gcm's own error type
    Argon2(argon2::Error),
    Bincode(bincode::Error),
    Pdf(printpdf::Error),
    InvalidFileFormat(String),
    PasswordIncorrect,
    MaxAttemptsReached,
    FileCorrupted(String), // Added context
    InputFileNotFound(String),
    OutputPathError(String),
    Utf8Error(std::string::FromUtf8Error),
    Custom(String),
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::Io(e) => write!(f, "IO Error: {}", e),
            EncryptError::Crypto(e) => write!(f, "Cryptography Error: {}", e),
            EncryptError::Argon2(e) => write!(f, "Key Derivation Error: {}", e),
            EncryptError::Bincode(e) => write!(f, "Serialization Error: {}", e),
            EncryptError::Pdf(e) => write!(f, "PDF Generation Error: {}", e),
            EncryptError::InvalidFileFormat(s) => write!(f, "Invalid File Format: {}", s),
            EncryptError::PasswordIncorrect => write!(f, "Password incorrect. Attempts remaining will be reduced."),
            EncryptError::MaxAttemptsReached => write!(f, "Maximum decryption attempts reached. File is now locked/corrupted."),
            EncryptError::FileCorrupted(s) => write!(f, "File is corrupted or tampered with: {}", s),
            EncryptError::InputFileNotFound(s) => write!(f, "Input file not found: {}", s),
            EncryptError::OutputPathError(s) => write!(f, "Could not determine output path: {}", s),
            EncryptError::Utf8Error(e) => write!(f, "UTF-8 decoding error: {}", e),
            EncryptError::Custom(s) => write!(f, "Error: {}", s),
        }
    }
}

// Implement From traits for easier error conversion
impl From<std::io::Error> for EncryptError { fn from(err: std::io::Error) -> EncryptError { EncryptError::Io(err) } }
impl From<aes_gcm::Error> for EncryptError { fn from(err: aes_gcm::Error) -> EncryptError { EncryptError::Crypto(err) } }
impl From<argon2::Error> for EncryptError { fn from(err: argon2::Error) -> EncryptError { EncryptError::Argon2(err) } }
impl From<bincode::Error> for EncryptError { fn from(err: bincode::Error) -> EncryptError { EncryptError::Bincode(err) } }
impl From<printpdf::Error> for EncryptError { fn from(err: printpdf::Error) -> EncryptError { EncryptError::Pdf(err) } }
impl From<std::string::FromUtf8Error> for EncryptError { fn from(err: std::string::FromUtf8Error) -> EncryptError { EncryptError::Utf8Error(err) } }

pub type Result<T> = std::result::Result<T, EncryptError>;