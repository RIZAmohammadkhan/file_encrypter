use printpdf::*;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use crate::error::{EncryptError, Result}; // Assuming Result is type alias from error module
use crate::file_format::{PDF_EMBED_START_MARKER, PDF_EMBED_END_MARKER};
use crate::crypto::find_subsequence;

// For Markdown parsing
use pulldown_cmark::{Parser as MarkdownParser, Event as MarkdownEvent, Tag as MarkdownTag, Options as MarkdownOptions, TagEnd};


const AVG_CHAR_WIDTH_MM_APPROX: f32 = 2.0; // Used for rough line width estimation

#[derive(Debug, Clone, Copy, PartialEq)]
enum TextStyle {
    Plain,
    Bold,
    Italic,
    BoldItalic,
}

// Helper to determine style from the stack (handles nested strong/emphasis)
fn determine_effective_style(style_stack: &[MarkdownTag]) -> TextStyle {
    let mut is_bold = false;
    let mut is_italic = false;
    for tag in style_stack.iter().rev() { // Iterate to find outermost relevant styles
        match tag {
            MarkdownTag::Strong => is_bold = true,
            MarkdownTag::Emphasis => is_italic = true,
            _ => {}
        }
    }

    if is_bold && is_italic {
        TextStyle::BoldItalic
    } else if is_bold {
        TextStyle::Bold
    } else if is_italic {
        TextStyle::Italic
    } else {
        TextStyle::Plain
    }
}


pub fn create_disguised_pdf(
    output_path: &Path,
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

    let font_plain = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_italic = doc.add_builtin_font(BuiltinFont::HelveticaOblique)?;
    let font_bold_italic = doc.add_builtin_font(BuiltinFont::HelveticaBoldOblique)?;

    current_layer.begin_text_section();

    // --- FIX: Set the line height ---
    let line_height_multiplier = 1.3; // Adjust this value as needed (e.g., 1.2 to 1.5)
    current_layer.set_line_height(text_font_size_pt * line_height_multiplier);
    // --- END FIX ---

    // Set initial cursor position (baseline of the first line)
    let font_size_mm = text_font_size_pt / 72.0 * 25.4; // Convert points to mm for cursor positioning
    current_layer.set_text_cursor(Mm(margin_mm), Mm(page_height_mm - margin_mm - font_size_mm));

    let usable_width_mm = page_width_mm - (2.0 * margin_mm);
    let max_chars_per_line = (usable_width_mm / AVG_CHAR_WIDTH_MM_APPROX).floor() as usize;

    if max_chars_per_line == 0 {
        return Err(EncryptError::PdfCreationLogicError("Calculated max_chars_per_line is zero. Check page/font dimensions or AVG_CHAR_WIDTH_MM_APPROX.".to_string()));
    }

    let mut markdown_options = MarkdownOptions::empty();
    markdown_options.insert(MarkdownOptions::ENABLE_STRIKETHROUGH);

    let parser = MarkdownParser::new_ext(display_text, markdown_options);
    
    let mut current_style_stack: Vec<MarkdownTag> = Vec::new();
    let mut current_line_char_count: usize = 0;
    let mut on_new_line = true;

    for event in parser {
        match event {
            MarkdownEvent::Start(tag) => {
                match &tag {
                    MarkdownTag::Paragraph => {
                        if !on_new_line { // If the previous content didn't end with a line break
                            current_layer.add_line_break();
                            current_line_char_count = 0;
                        }
                        on_new_line = true; 
                    }
                    MarkdownTag::Strong | MarkdownTag::Emphasis => {
                        current_style_stack.push(tag.clone()); // Clone the tag for the stack
                    }
                    _ => {}
                }
            }
            MarkdownEvent::End(tag_end) => { // tag_end is pulldown_cmark::TagEnd
                match tag_end {
                    TagEnd::Paragraph => {
                        if !on_new_line { // If paragraph had content and didn't end on a fresh line
                            current_layer.add_line_break();
                        }
                        current_line_char_count = 0;
                        on_new_line = true;
                    }
                    TagEnd::Strong => {
                        // Pop if the last tag on stack is Strong
                        if let Some(MarkdownTag::Strong) = current_style_stack.last() {
                            current_style_stack.pop();
                        }
                    }
                    TagEnd::Emphasis => {
                        // Pop if the last tag on stack is Emphasis
                        if let Some(MarkdownTag::Emphasis) = current_style_stack.last() {
                            current_style_stack.pop();
                        }
                    }
                    _ => {} // Handle other end tags if needed
                }
            }
            MarkdownEvent::Text(text_cow) => {
                let text_segment = text_cow.into_string();
                // ==========================================================
                //  THIS IS THE LINE (AROUND 142) THAT NEEDS TO BE CORRECT:
                // ==========================================================
                let effective_style = determine_effective_style(&current_style_stack);
                // ==========================================================
                
                let font_ref = match effective_style {
                    TextStyle::Plain => &font_plain,
                    TextStyle::Bold => &font_bold,
                    TextStyle::Italic => &font_italic,
                    TextStyle::BoldItalic => &font_bold_italic,
                };
                current_layer.set_font(font_ref, text_font_size_pt);

                let mut remaining_text_in_segment = text_segment.as_str();
                while !remaining_text_in_segment.is_empty() {
                    let text_to_write: String;
                    let mut ends_with_linebreak = false;

                    if on_new_line {
                        remaining_text_in_segment = remaining_text_in_segment.trim_start_matches(|c: char| c.is_whitespace() && c != '\n');
                        if remaining_text_in_segment.is_empty() { break; } 
                    }
                    
                    let current_segment_char_count = remaining_text_in_segment.chars().count();
                    if current_line_char_count + current_segment_char_count <= max_chars_per_line {
                        text_to_write = remaining_text_in_segment.to_string();
                        remaining_text_in_segment = ""; 
                    } else {
                        let available_chars_on_line = max_chars_per_line.saturating_sub(current_line_char_count);
                        
                        if available_chars_on_line == 0 { 
                            text_to_write = "".to_string(); 
                        } else {
                            let mut split_at_byte_idx = 0;
                            let mut chars_taken = 0;
                            let mut last_space_byte_idx: Option<usize> = None;

                            for (byte_idx, char_val) in remaining_text_in_segment.char_indices() {
                                if chars_taken >= available_chars_on_line {
                                    split_at_byte_idx = byte_idx; 
                                    break;
                                }
                                if char_val.is_whitespace() && char_val != '\n' {
                                    last_space_byte_idx = Some(byte_idx + char_val.len_utf8());
                                }
                                split_at_byte_idx = byte_idx + char_val.len_utf8();
                                chars_taken += 1;
                            }

                            if let Some(space_idx) = last_space_byte_idx {
                                if space_idx <= split_at_byte_idx {
                                     split_at_byte_idx = space_idx;
                                }
                            }
                            text_to_write = remaining_text_in_segment[..split_at_byte_idx].to_string();
                            remaining_text_in_segment = &remaining_text_in_segment[split_at_byte_idx..];
                        }
                        ends_with_linebreak = true; 
                    }

                    if !text_to_write.is_empty() {
                        current_layer.write_text(text_to_write.clone(), font_ref);
                        current_line_char_count += text_to_write.chars().count();
                        on_new_line = false; 
                    }

                    if ends_with_linebreak {
                        current_layer.add_line_break();
                        current_line_char_count = 0;
                        on_new_line = true;
                    }
                }
            }
            MarkdownEvent::HardBreak => { 
                current_layer.add_line_break();
                current_line_char_count = 0;
                on_new_line = true;
            }
            MarkdownEvent::SoftBreak => { 
                if current_line_char_count > 0 { 
                    if current_line_char_count + 1 <= max_chars_per_line {
                        current_layer.set_font(&font_plain, text_font_size_pt); 
                        current_layer.write_text(" ".to_string(), &font_plain);
                        current_line_char_count += 1;
                        on_new_line = false;
                    } else {
                        current_layer.add_line_break();
                        current_line_char_count = 0;
                        on_new_line = true;
                    }
                }
            }
            MarkdownEvent::Rule => { 
                 if !on_new_line {
                    current_layer.add_line_break();
                 }
                current_layer.set_font(&font_plain, text_font_size_pt);
                let rule_text = "-".repeat(std::cmp::min(max_chars_per_line, 20)); 
                current_layer.write_text(rule_text, &font_plain);
                current_layer.add_line_break();
                current_line_char_count = 0;
                on_new_line = true;
            }
            _ => {}
        }
    }
    current_layer.end_text_section();


    // --- Embedding encrypted data ---
    let mut pdf_bytes_buffer = Vec::new();
    doc.save(&mut BufWriter::new(&mut pdf_bytes_buffer))?;

    let mut final_content = pdf_bytes_buffer;
    final_content.extend_from_slice(PDF_EMBED_START_MARKER);
    let metadata_len_bytes = (serialized_metadata.len() as u64).to_be_bytes();
    final_content.write_all(&metadata_len_bytes)?;
    final_content.write_all(serialized_metadata)?;
    final_content.write_all(ciphertext)?;
    final_content.extend_from_slice(PDF_EMBED_END_MARKER);
    std::fs::write(output_path, final_content)?;

    Ok(())
}

pub fn extract_data_from_pdf(pdf_path: &Path) -> Result<Vec<u8>> {
    let mut file_content = Vec::new();
    File::open(pdf_path)?.read_to_end(&mut file_content)?;

    let start_marker_pos = find_subsequence(&file_content, PDF_EMBED_START_MARKER)
        .ok_or_else(|| EncryptError::InvalidFileFormat("PDF start marker not found.".to_string()))?;

    let data_payload_start_offset = start_marker_pos + PDF_EMBED_START_MARKER.len();

    let search_area_for_end_marker = &file_content[data_payload_start_offset..];

    let end_marker_relative_pos = find_subsequence(search_area_for_end_marker, PDF_EMBED_END_MARKER)
        .ok_or_else(|| EncryptError::InvalidFileFormat("PDF end marker not found after start marker payload.".to_string()))?;
    
    let end_marker_absolute_pos_of_payload_end = data_payload_start_offset + end_marker_relative_pos;

    if data_payload_start_offset > end_marker_absolute_pos_of_payload_end {
        return Err(EncryptError::InvalidFileFormat("PDF markers are in incorrect order or data payload is missing.".to_string()));
    }

    Ok(file_content[data_payload_start_offset .. end_marker_absolute_pos_of_payload_end].to_vec())
}