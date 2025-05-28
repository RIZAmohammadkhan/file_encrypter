use serde::{Serialize, Deserialize};

pub const MAX_DECRYPTION_ATTEMPTS: u8 = 3;
pub const ENCR_FILE_EXTENSION: &str = "encr";
pub const PDF_FILE_EXTENSION: &str = "pdf";

// Markers for disguised PDF data - chosen to be somewhat unique
pub const PDF_EMBED_START_MARKER: &[u8] = b"__::ENCR_DATA_S::_ safeguarded by rustacean magic _::_S_::ENCR_DATA_START::__";
pub const PDF_EMBED_END_MARKER: &[u8] = b"__::ENCR_DATA_E::_ property of the crab _::_E_::ENCR_DATA_END::__";


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMetadata {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_verification_hash: Vec<u8>, // Hash of the derived key (Argon2(password, salt))
    pub decryption_attempts: u8,
    pub original_extension: Option<String>, // To restore original file type
}

impl FileMetadata {
    pub fn new(salt: Vec<u8>, nonce: Vec<u8>, key_verification_hash: Vec<u8>, original_extension: Option<String>) -> Self {
        FileMetadata {
            salt,
            nonce,
            key_verification_hash,
            decryption_attempts: 0,
            original_extension,
        }
    }
}