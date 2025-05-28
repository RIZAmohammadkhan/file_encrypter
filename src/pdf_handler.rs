use printpdf::*;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path; // <<< Changed PathBuf back to Path where appropriate

use crate::error::{EncryptError, Result};
use crate::file_format::{PDF_EMBED_START_MARKER, PDF_EMBED_END_MARKER};
use crate::crypto::find_subsequence;

const AVG_CHAR_WIDTH_MM_APPROX: f32 = 2.0;

pub fn create_disguised_pdf(
    output_path: &Path, // <<< Changed back to &Path
    display_text: &str,
    serialized_metadata: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    let page_width_mm = 210.0;
    let page_height_mm = 297.0;
    let margin_mm = 20.0;
    let text_font_size_pt = 12.0;

    let (doc, page1, layer1) = PdfDocument::new(
        "Disguised Document",
        Mm(page_width_mm),
        Mm(page_height_mm),
        "Layer 1",
    );
    let current_layer = doc.get_page(page1).get_layer(layer1);
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;

    current_layer.set_font(&font, text_font_size_pt);
    current_layer.begin_text_section();

    current_layer.set_text_cursor(Mm(margin_mm), Mm(page_height_mm - margin_mm - text_font_size_pt / 2.0));

    let usable_width_mm = page_width_mm - (2.0 * margin_mm);
    let max_chars_per_line = (usable_width_mm / AVG_CHAR_WIDTH_MM_APPROX).floor() as usize;

    for paragraph in display_text.split('\n') {
        let mut current_line_text = String::new();
        for word in paragraph.split_whitespace() {
            if current_line_text.is_empty() {
                current_line_text.push_str(word);
            } else {
                if current_line_text.len() + word.len() + 1 > max_chars_per_line && !current_line_text.is_empty() {
                    current_layer.write_text(current_line_text.trim(), &font);
                    current_layer.add_line_break();
                    current_line_text.clear();
                    current_line_text.push_str(word);
                } else {
                    current_line_text.push(' ');
                    current_line_text.push_str(word);
                }
            }
        }
        if !current_line_text.is_empty() {
            current_layer.write_text(current_line_text.trim(), &font);
            current_layer.add_line_break();
        } else if paragraph.is_empty() && display_text.contains("\n\n") {
             current_layer.add_line_break();
        }
    }

    current_layer.end_text_section();

    let mut pdf_bytes_buffer = Vec::new();
    doc.save(&mut BufWriter::new(&mut pdf_bytes_buffer))?;

    let mut final_content = pdf_bytes_buffer;
    final_content.extend_from_slice(PDF_EMBED_START_MARKER);
    let metadata_len_bytes = (serialized_metadata.len() as u64).to_be_bytes();
    final_content.write_all(&metadata_len_bytes)?;
    final_content.write_all(serialized_metadata)?;
    final_content.write_all(ciphertext)?;
    final_content.extend_from_slice(PDF_EMBED_END_MARKER);
    std::fs::write(output_path, final_content)?; // output_path is &Path, works fine

    Ok(())
}

pub fn extract_data_from_pdf(pdf_path: &Path) -> Result<Vec<u8>> { // <<< Changed back to &Path
    let mut file_content = Vec::new();
    File::open(pdf_path)?.read_to_end(&mut file_content)?; // pdf_path is &Path, works fine

    let start_marker_pos = find_subsequence(&file_content, PDF_EMBED_START_MARKER)
        .ok_or_else(|| EncryptError::InvalidFileFormat("PDF start marker not found.".to_string()))?;

    let data_payload_start_offset = start_marker_pos + PDF_EMBED_START_MARKER.len();

    let end_marker_relative_pos = find_subsequence(&file_content[data_payload_start_offset..], PDF_EMBED_END_MARKER)
        .ok_or_else(|| EncryptError::InvalidFileFormat("PDF end marker not found after start marker payload.".to_string()))?;

    let end_marker_absolute_pos_of_payload_end = data_payload_start_offset + end_marker_relative_pos;

    if data_payload_start_offset > end_marker_absolute_pos_of_payload_end {
        return Err(EncryptError::InvalidFileFormat("PDF markers are in incorrect order or data payload is missing.".to_string()));
    }

    Ok(file_content[data_payload_start_offset .. end_marker_absolute_pos_of_payload_end].to_vec())
}