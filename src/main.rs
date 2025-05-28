#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod error;
mod file_format;
mod pdf_handler;

use eframe::egui::{self, Align, Layout, Sense}; // Sense is used for clickable labels
use rfd::FileDialog; // FileDialog is used
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use error::EncryptError;

#[derive(PartialEq, Clone, Copy)]
enum AppMode {
    Encrypt,
    Decrypt,
}

enum OperationState {
    Idle,
    Working(String),
    Success(String),
    Error(String),
}

struct FileEncrypterApp {
    mode: AppMode,
    input_file: Option<PathBuf>,
    output_directory: Option<PathBuf>,
    output_filename_stem: String,
    password: String,
    password_confirm: String,
    disguise_as_pdf: bool,
    pdf_display_text: String,
    operation_state: OperationState,
    op_sender: Sender<std::result::Result<String, EncryptError>>,
    op_receiver: Receiver<std::result::Result<String, EncryptError>>,
    last_mode: AppMode,
    last_disguise_state: bool,
}

impl Default for FileEncrypterApp {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self {
            mode: AppMode::Encrypt,
            input_file: None,
            output_directory: None,
            output_filename_stem: String::new(),
            password: String::new(),
            password_confirm: String::new(),
            disguise_as_pdf: false,
            pdf_display_text: "This document has been secured.\n\nPlease use the dedicated viewer application to access its contents.".to_string(),
            operation_state: OperationState::Idle,
            op_sender: tx,
            op_receiver: rx,
            last_mode: AppMode::Encrypt,
            last_disguise_state: false,
        }
    }
}

impl FileEncrypterApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Default::default()
    }

    fn get_full_output_path(&self) -> Option<PathBuf> {
        if let Some(dir) = &self.output_directory {
            if !self.output_filename_stem.is_empty() {
                let mut path = dir.join(&self.output_filename_stem);
                match self.mode {
                    AppMode::Encrypt => {
                        if self.disguise_as_pdf {
                            path.set_extension(file_format::PDF_FILE_EXTENSION);
                        } else {
                            path.set_extension(file_format::ENCR_FILE_EXTENSION);
                        }
                    }
                    AppMode::Decrypt => { /* No extension set here; decrypt_file handles original ext */ }
                }
                return Some(path);
            }
        }
        None
    }

    fn suggest_output_name_and_dir(&mut self) {
        if let Some(input_path) = &self.input_file {
            self.output_directory = input_path.parent().map(PathBuf::from);
            if self.output_directory.is_none() {
                self.output_directory = Some(PathBuf::from("."));
            }
            let input_filename_stem_str = input_path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
            let suggested_stem = match self.mode {
                AppMode::Encrypt => format!("{}_encrypted", input_filename_stem_str),
                AppMode::Decrypt => {
                    let mut base = input_filename_stem_str.to_string();
                    // Try to remove known suffixes
                    if let Some(stripped) = base.strip_suffix("_encrypted") {
                        base = stripped.to_string();
                    } else if let Some(stripped) = base.strip_suffix(&format!(".{}", file_format::ENCR_FILE_EXTENSION)) {
                        base = stripped.to_string();
                    } else if let Some(stripped) = base.strip_suffix(&format!(".{}", file_format::PDF_FILE_EXTENSION)) { // If it was disguised
                        base = stripped.to_string();
                    } else {
                        base = format!("{}_decrypted", input_filename_stem_str);
                    }
                    base
                }
            };
            self.output_filename_stem = suggested_stem;
        } else {
            self.output_directory = None;
            self.output_filename_stem.clear();
        }
    }

    fn handle_encryption(&mut self) {
        if self.password.is_empty() { self.operation_state = OperationState::Error("Password cannot be empty.".to_string()); return; }
        if self.password != self.password_confirm { self.operation_state = OperationState::Error("Passwords do not match.".to_string()); return; }
        let input_path = match &self.input_file { Some(p) => p.clone(), None => { self.operation_state = OperationState::Error("No input file selected.".to_string()); return; } };
        let output_path = match self.get_full_output_path() { Some(p) => p, None => { self.operation_state = OperationState::Error("Output directory or filename is not set.".to_string()); return; } };
        if input_path == output_path { self.operation_state = OperationState::Error("Input and output file paths cannot be the same.".to_string()); return; }

        self.operation_state = OperationState::Working("Encrypting...".to_string());
        let password_clone = self.password.clone();
        let disguise = self.disguise_as_pdf;
        let pdf_text_clone = if disguise { Some(self.pdf_display_text.clone()) } else { None };
        let sender = self.op_sender.clone();
        thread::spawn(move || {
            let result = crypto::encrypt_file(&input_path, &output_path, &password_clone, disguise, pdf_text_clone);
            match result {
                Ok(_) => sender.send(Ok(format!("Successfully encrypted to\n{}", output_path.display()))),
                Err(e) => sender.send(Err(e)),
            }.expect("Failed to send operation result");
        });
    }

    fn handle_decryption(&mut self) {
        if self.password.is_empty() { self.operation_state = OperationState::Error("Password cannot be empty.".to_string()); return; }
        let input_path = match &self.input_file { Some(p) => p.clone(), None => { self.operation_state = OperationState::Error("No input file selected.".to_string()); return; } };
        let output_base_path_for_crypto = match self.get_full_output_path() { Some(p) => p, None => { self.operation_state = OperationState::Error("Output directory or filename is not set for decryption base.".to_string()); return; } };

        self.operation_state = OperationState::Working("Decrypting...".to_string());
        let password_clone = self.password.clone();
        let sender = self.op_sender.clone();
        thread::spawn(move || {
            let result = crypto::decrypt_file(&input_path, &output_base_path_for_crypto, &password_clone);
            match result {
                Ok(final_path) => sender.send(Ok(format!("Successfully decrypted to\n{}", final_path.display()))),
                Err(e) => sender.send(Err(e)),
            }.expect("Failed to send operation result");
        });
    }

    // Corrected ui_input_file_selector
    fn ui_input_file_selector(ui: &mut egui::Ui, _label_ignored: &str, path_opt: &mut Option<PathBuf>) -> bool {
        let mut changed = false;
        // ui is the grid cell's ui. We fill this cell with a horizontal layout.
        ui.horizontal(|item_ui| { // item_ui is for the content of this new horizontal strip
            let display_text = path_opt.as_ref().map_or_else(|| "None".to_string(), |p| p.display().to_string());

            // Label on the left, truncate if too long, make it clickable
            let label_response = item_ui.add(egui::Label::new(display_text).truncate(true).sense(Sense::click()));
            if label_response.clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    *path_opt = Some(path);
                    changed = true;
                }
            }
            
            // Buttons on the right side of the horizontal layout.
            item_ui.with_layout(Layout::right_to_left(Align::Center), |button_ui| {
                // Add buttons from right to left (innermost right first).
                if path_opt.is_some() {
                    if button_ui.button("❌").on_hover_text("Clear selection").clicked() {
                        *path_opt = None;
                        changed = true;
                    }
                }
                if button_ui.button("Browse...").on_hover_text("Select input file").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        *path_opt = Some(path);
                        changed = true;
                    }
                }
            });
        });
        changed
    }
}

impl eframe::App for FileEncrypterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mode_changed = self.mode != self.last_mode;
        let disguise_state_changed_in_encrypt_mode = self.mode == AppMode::Encrypt && self.disguise_as_pdf != self.last_disguise_state;

        if mode_changed || disguise_state_changed_in_encrypt_mode {
            if self.input_file.is_some() { self.suggest_output_name_and_dir(); }
            self.last_mode = self.mode;
            self.last_disguise_state = self.disguise_as_pdf;
            if mode_changed && self.mode == AppMode::Decrypt { self.password_confirm.clear(); }
        }

        if let Ok(op_result) = self.op_receiver.try_recv() {
            match op_result {
                Ok(msg) => { self.operation_state = OperationState::Success(msg); if let AppMode::Encrypt = self.mode { self.password_confirm.clear(); self.password.clear(); } }
                Err(e) => { self.operation_state = OperationState::Error(e.to_string());}
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Universal File Encrypter");
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode, AppMode::Encrypt, "🔒 Encrypt");
                ui.selectable_value(&mut self.mode, AppMode::Decrypt, "🔓 Decrypt");
            });
            ui.separator();
            ui.add_space(5.0);

            egui::Grid::new("file_io_grid")
                .num_columns(2)
                .spacing([10.0, 8.0])
                .min_col_width(100.0) // Width for the labels column
                // The second column will take the rest of the available width.
                .show(ui, |ui| {
                    ui.label("Input File:");
                    // The ui_input_file_selector now handles its own horizontal layout within this grid cell
                    if FileEncrypterApp::ui_input_file_selector(ui, "", &mut self.input_file) {
                        self.suggest_output_name_and_dir();
                    }
                    ui.end_row();

                    ui.label("Output In:");
                    // Corrected layout for Output In row
                    ui.horizontal(|item_ui| {
                        let dir_display = self.output_directory.as_ref().map_or_else(|| "N/A".to_string(), |p| p.display().to_string());
                        item_ui.add(egui::Label::new(dir_display).truncate(true)); // Truncate if path is too long
                        
                        item_ui.with_layout(Layout::right_to_left(Align::Center), |button_ui| {
                            if button_ui.button("Change...").on_hover_text("Select different output directory").clicked() {
                                 if let Some(path) = FileDialog::new().pick_folder() {
                                     self.output_directory = Some(path);
                                     // If you need to react to this change immediately, set a flag or call a method
                                 }
                            }
                        });
                    });
                    ui.end_row();

                    ui.label("Output Name:");
                    ui.horizontal(|ui| { 
                        ui.add(egui::TextEdit::singleline(&mut self.output_filename_stem).hint_text("filename (no ext.)").desired_width(200.0));
                        let auto_ext = if self.output_filename_stem.is_empty() && self.output_directory.is_none() { "".to_string() }
                                       else if self.output_filename_stem.is_empty() { "(type name)".to_string() }
                                       else { match self.mode {
                                           AppMode::Encrypt => if self.disguise_as_pdf { format!(".{}", file_format::PDF_FILE_EXTENSION) } else { format!(".{}", file_format::ENCR_FILE_EXTENSION) },
                                           AppMode::Decrypt => "".to_string(), }}; // Decrypt will use original name's extension
                        if !auto_ext.is_empty() && auto_ext != "(type name)" { ui.monospace(auto_ext); } 
                        else if auto_ext == "(type name)" { ui.weak(auto_ext); }
                    });
                    ui.end_row();

                    ui.label("🔑 Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
                    ui.end_row();

                    if let AppMode::Encrypt = self.mode {
                        ui.label("🔑 Confirm:");
                        ui.add(egui::TextEdit::singleline(&mut self.password_confirm).password(true).desired_width(f32::INFINITY));
                        ui.end_row();

                        ui.label(""); // For grid alignment
                        if ui.checkbox(&mut self.disguise_as_pdf, "Disguise as PDF").on_hover_text("Embed encrypted data within a valid, but minimal, PDF structure.").changed() {
                            if self.input_file.is_some() { self.suggest_output_name_and_dir(); }
                        }
                        ui.end_row();
                    }
                });

            if self.mode == AppMode::Encrypt && self.disguise_as_pdf {
                ui.add_space(5.0);
                ui.indent("pdf_text_indent", |ui| {
                    ui.label("PDF Display Text (auto-wraps in PDF):");
                    ui.add(egui::TextEdit::multiline(&mut self.pdf_display_text).desired_rows(4).desired_width(f32::INFINITY).hint_text("Enter text that will be visible in the placeholder PDF..."));
                });
            }
            
            ui.add_space(15.0);
            ui.vertical_centered_justified(|ui| { 
                 let action_button_text = match self.mode { AppMode::Encrypt => "🔒 Encrypt File", AppMode::Decrypt => "🔓 Decrypt File", };
                 let output_path_is_valid = self.get_full_output_path().is_some();
                 let button_enabled = !matches!(self.operation_state, OperationState::Working(_)) && self.input_file.is_some() &&
                                      output_path_is_valid && !self.password.is_empty() &&
                                      (self.mode == AppMode::Decrypt || (!self.password_confirm.is_empty() && self.password == self.password_confirm));
                 if ui.add_enabled(button_enabled, egui::Button::new(action_button_text).min_size(egui::vec2(150.0, 35.0))).clicked() {
                     match self.mode { AppMode::Encrypt => self.handle_encryption(), AppMode::Decrypt => self.handle_decryption(), }
                 }
            });
            ui.add_space(10.0);

            match &self.operation_state { 
                OperationState::Idle => { ui.label("Ready. Select mode, files, and enter password."); }
                OperationState::Working(msg) => { ui.horizontal(|ui|{ ui.spinner(); ui.label(msg); }); }
                OperationState::Success(msg) => { ui.label(egui::RichText::new(msg).color(egui::Color32::GREEN).strong()); }
                OperationState::Error(msg) => { ui.label(egui::RichText::new(format!("❌ Error: {}", msg)).color(egui::Color32::RED).strong()); }
            }
             ui.add_space(20.0); ui.separator();
             ui.horizontal(|ui| { 
                if ui.link("Source Code").clicked() {
                    ui.ctx().open_url(egui::output::OpenUrl::new_tab("https://github.com/RIZAmohammadkhan/file_encrypter"));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("v{}", env!("CARGO_PKG_VERSION"))); 
                    egui::warn_if_debug_build(ui);
                });
             });
        });
        ctx.request_repaint_after(std::time::Duration::from_millis(100)); // For spinner updates
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 650.0]) 
            .with_min_inner_size([700.0, 550.0]), 
        ..Default::default()
    };
    eframe::run_native("Universal File Encrypter", native_options, Box::new(|cc| Box::new(FileEncrypterApp::new(cc))))
}