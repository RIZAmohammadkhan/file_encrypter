use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit}; // <<< Added KeyInit
use aes_gcm::aead::{Aead, OsRng}; // <<< Removed NewAead
// use argon2::password_hash::{PasswordHasher, SaltString, PasswordHash, PasswordVerifier}; // <<< Removed unused imports
use argon2::{Argon2, Params, Version, Algorithm};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom, Cursor}; // Cursor is used here
use std::path::{Path, PathBuf};

use crate::file_format::{FileMetadata, MAX_DECRYPTION_ATTEMPTS, PDF_EMBED_START_MARKER, PDF_EMBED_END_MARKER};
use crate::error::{EncryptError, Result}; // Result is used here
use crate::pdf_handler;

const KEY_SIZE: usize = 32; 
const NONCE_SIZE: usize = 12; 
const SALT_SIZE: usize = 16; 
const APPROX_MAX_METADATA_SERIALIZED_SIZE: usize = 128; 

pub(crate) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn derive_key(password: &str, salt_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut key_material = vec![0u8; KEY_SIZE];
    let params = Params::new(19456, 2, 1, Some(KEY_SIZE))
        .map_err(|e| EncryptError::Custom(format!("Argon2 params error: {}", e)))?;
    
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key_material)
        .map_err(EncryptError::Argon2)?;
    Ok(key_material)
}

fn hash_key_for_verification(key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.finalize().to_vec()
}

pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    disguise_as_pdf: bool,
    pdf_text: Option<String>,
) -> Result<()> {
    if !input_path.exists() {
        return Err(EncryptError::InputFileNotFound(input_path.display().to_string()));
    }

    let mut input_file = File::open(input_path)?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;
    drop(input_file); 

    let mut salt = vec![0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let derived_key_vec = derive_key(password, &salt)?;
    let key_verification_hash = hash_key_for_verification(&derived_key_vec); 
    let aes_key_generic_array = Key::<Aes256Gcm>::from_slice(&derived_key_vec); // This creates a GenericArray

    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Correct way to initialize Aes256Gcm with KeyInit trait
    let cipher = Aes256Gcm::new(aes_key_generic_array); // <<< Uses KeyInit now
    let ciphertext = cipher.encrypt(nonce, plaintext.as_slice())?; 
    
    let original_extension = input_path.extension().and_then(|os_str| os_str.to_str()).map(String::from);

    let metadata = FileMetadata::new(salt, nonce_bytes, key_verification_hash, original_extension);
    let serialized_metadata = bincode::serialize(&metadata)?;

    if disguise_as_pdf {
        let display_text = pdf_text.unwrap_or_else(|| "This document is protected.".to_string());
        pdf_handler::create_disguised_pdf(output_path, &display_text, &serialized_metadata, &ciphertext)?;
    } else {
        let mut output_file = File::create(output_path)?;
        let metadata_len_bytes = (serialized_metadata.len() as u64).to_be_bytes();
        output_file.write_all(&metadata_len_bytes)?;
        output_file.write_all(&serialized_metadata)?;
        output_file.write_all(&ciphertext)?;
    }

    Ok(())
}

fn read_encrypted_parts_from_stream<R: Read>(mut reader: R) -> Result<(FileMetadata, Vec<u8>)> {
    let mut metadata_len_bytes = [0u8; 8];
    reader.read_exact(&mut metadata_len_bytes)
        .map_err(|_| EncryptError::InvalidFileFormat("Failed to read metadata length".to_string()))?;
    let metadata_len = u64::from_be_bytes(metadata_len_bytes) as usize;

    if metadata_len > APPROX_MAX_METADATA_SERIALIZED_SIZE * 2 { 
        return Err(EncryptError::InvalidFileFormat(format!("Reported metadata size ({}) is suspiciously large.", metadata_len)));
    }

    let mut serialized_metadata = vec![0u8; metadata_len];
    reader.read_exact(&mut serialized_metadata)
        .map_err(|_| EncryptError::InvalidFileFormat("Failed to read metadata block".to_string()))?;
    
    let metadata: FileMetadata = bincode::deserialize(&serialized_metadata)
        .map_err(|e| EncryptError::InvalidFileFormat(format!("Failed to deserialize metadata: {}", e)))?;
    
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;
    
    Ok((metadata, ciphertext))
}


pub fn decrypt_file(
    input_path: &Path,
    output_base_path: &Path, 
    password: &str,
) -> Result<PathBuf> {
    if !input_path.exists() {
        return Err(EncryptError::InputFileNotFound(input_path.display().to_string()));
    }

    let (mut metadata, ciphertext_vec, is_disguised) = if input_path.extension().map_or(false, |ext| ext == "pdf") {
        let encrypted_blob = pdf_handler::extract_data_from_pdf(input_path)?;
        let (meta, cipher_vec) = read_encrypted_parts_from_stream(Cursor::new(&encrypted_blob))?;
        (meta, cipher_vec, true)
    } else {
        let input_file = File::open(input_path)?;
        let (meta, cipher_vec) = read_encrypted_parts_from_stream(input_file)?;
        (meta, cipher_vec, false)
    };

    if metadata.decryption_attempts >= MAX_DECRYPTION_ATTEMPTS {
        return Err(EncryptError::MaxAttemptsReached);
    }

    let derived_key_vec = derive_key(password, &metadata.salt)?;
    let current_key_verification_hash = hash_key_for_verification(&derived_key_vec);

    if current_key_verification_hash != metadata.key_verification_hash {
        metadata.decryption_attempts += 1;
        let should_corrupt = metadata.decryption_attempts >= MAX_DECRYPTION_ATTEMPTS;

        if should_corrupt {
            OsRng.fill_bytes(&mut metadata.salt); 
        }
        
        let new_serialized_metadata = bincode::serialize(&metadata)?;

        if is_disguised {
            let original_pdf_data = std::fs::read(input_path)?;
            if let Some(start_offset) = find_subsequence(&original_pdf_data, PDF_EMBED_START_MARKER) {
                // We need to find the end marker based on its content, not just any end marker in the file.
                // The end marker should be *after* the start marker + our data.
                // For simplicity, assume original_pdf_data[end_offset..] points to the start of PDF_EMBED_END_MARKER
                let data_start = start_offset + PDF_EMBED_START_MARKER.len();
                if let Some(end_marker_relative_start) = find_subsequence(&original_pdf_data[data_start..], PDF_EMBED_END_MARKER) {
                    let end_offset = data_start + end_marker_relative_start; // Absolute start of the end marker
                    
                    let mut new_pdf_content = Vec::new();
                    new_pdf_content.extend_from_slice(&original_pdf_data[..start_offset + PDF_EMBED_START_MARKER.len()]);
                    
                    let metadata_len_bytes = (new_serialized_metadata.len() as u64).to_be_bytes();
                    new_pdf_content.extend_from_slice(&metadata_len_bytes);
                    new_pdf_content.extend_from_slice(&new_serialized_metadata);
                    
                    new_pdf_content.extend_from_slice(&ciphertext_vec); 
                    new_pdf_content.extend_from_slice(&original_pdf_data[end_offset..]); 

                    std::fs::write(input_path, new_pdf_content)?;
                } else {
                    // End marker not found after start marker in the expected place.
                    // This is an issue for reliably updating the PDF.
                    // For now, the attempt count might not be saved for this PDF try.
                }
            }
        } else {
            let mut file = OpenOptions::new().write(true).open(input_path)?;
            file.seek(SeekFrom::Start(0))?; 
            let metadata_len_bytes = (new_serialized_metadata.len() as u64).to_be_bytes();
            file.write_all(&metadata_len_bytes)?;
            file.write_all(&new_serialized_metadata)?;
            file.set_len(8 + new_serialized_metadata.len() as u64 + ciphertext_vec.len() as u64)?; 
        }
        
        if should_corrupt {
            return Err(EncryptError::MaxAttemptsReached);
        }
        return Err(EncryptError::PasswordIncorrect);
    }

    let aes_key_generic_array = Key::<Aes256Gcm>::from_slice(&derived_key_vec);
    let nonce = Nonce::from_slice(&metadata.nonce);
    let cipher = Aes256Gcm::new(aes_key_generic_array); // <<< Uses KeyInit now

    let plaintext = cipher.decrypt(nonce, ciphertext_vec.as_slice())
        .map_err(|_| EncryptError::FileCorrupted("AEAD tag mismatch during decryption, data likely tampered or wrong key despite hash match (rare).".to_string()))?;

    let output_dir = output_base_path.parent().unwrap_or_else(|| Path::new(""));
    let output_filename_stem = output_base_path.file_stem().unwrap_or_default(); 
    
    let final_output_filename = if let Some(ext) = &metadata.original_extension {
        Path::new(output_filename_stem).with_extension(ext).file_name().unwrap_or_default().to_os_string()
    } else {
        Path::new(output_filename_stem).with_extension("bin").file_name().unwrap_or_default().to_os_string()
    };

    let final_output_path = output_dir.join(final_output_filename);
    
    std::fs::write(&final_output_path, plaintext)?;

    Ok(final_output_path)
}