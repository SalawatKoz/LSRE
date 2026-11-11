//! Вкладка «Код»: файлы проекта и просмотр текста без запуска и без правок.

use crate::theme::{self, Tokens};
use crate::CraftApp;
use egui::Ui;
use std::path::{Path, PathBuf};

const TEXT_EXT: &[&str] = &[
    "rs", "js", "mjs", "cjs", "ts", "json", "toml", "md", "txt", "yml", "yaml", "c", "h", "hpp", "cpp",
    "py", "cs", "html", "css", "sql", "kts", "ksy", "sh", "ps1", "bat", "cmd", "xml", "ini", "log",
];
const MAX_FILES: usize = 400;
const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_VIEW_LINES: usize = 6000;

fn is_text(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| TEXT_EXT.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if out.len() >= MAX_FILES || depth > 4 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut list: Vec<_> = entries.flatten().collect();
    list.sort_by_key(|e| e.file_name());
    for entry in list {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out, depth + 1);
        } else if is_text(&path) && entry.metadata().map(|m| m.len() < MAX_BYTES).unwrap_or(false) {
            out.push(path);
        }
        if out.len() >= MAX_FILES {
            return;
        }
    }
}

pub fn show(app: &mut CraftApp, ui: &mut Ui) {
    let t = Tokens::get(ui.ctx());
    let Some(workspace) = app.workspace.as_ref() else {
        empty(ui, &t);
        return;
    };
    let root = workspace.root.clone();
    let mut files = Vec::new();
    collect(&root, &root, &mut files, 0);

    let mut selected: Option<PathBuf> = ui.data(|d| d.get_temp::<Option<PathBuf>>(egui::Id::new("code-selected"))).flatten();
    ui.horizontal_top(|ui| {
        // Слева — список файлов.
        ui.allocate_ui_with_layout(egui::vec2(300.0, ui.available_height()), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.horizontal(|ui| {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(format!("Файлы ({})", files.len())).size(theme::CAPTION).color(t.text_faint));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Папка").on_hover_text("Открыть папку проекта").clicked() {
                        let _ = std::process::Command::new("explorer").arg(&root).spawn();
                    }
                });
            });
            ui.add_space(4.0);
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for path in &files {
                    let rel = path.strip_prefix(&root).unwrap_or(path).display().to_string();
                    let on = selected.as_deref() == Some(path.as_path());
                    let label = egui::RichText::new(&rel).size(theme::SMALL).color(if on { t.text } else { t.text_dim });
                    let resp = ui.add_sized([ui.available_width(), 24.0], egui::Button::new(label).selected(on).frame(false));
                    if resp.clicked() {
                        eprintln!("[LSRE] code: выбран {}", rel);
                        selected = Some(path.clone());
                    }
                }
                if files.is_empty() {
                    ui.label(egui::RichText::new("Текстовых файлов не найдено").size(theme::SMALL).color(t.text_faint));
                }
            });
        });
        ui.separator();
        // Справа — содержимое.
        ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), ui.available_height()), egui::Layout::top_down(egui::Align::Min), |ui| {
            match &selected {
                Some(path) if path.exists() => {
                    ui.horizontal(|ui| {
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new(path.strip_prefix(&root).unwrap_or(path).display().to_string()).size(theme::SMALL).color(t.text));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Копировать путь").clicked() {
                                ui.ctx().copy_text(path.display().to_string());
                            }
                        });
                    });
                    ui.add_space(4.0);
                    egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                        match std::fs::read_to_string(path) {
                            Ok(text) => {
                                let shown: String = text.lines().take(MAX_VIEW_LINES).collect::<Vec<_>>().join("\n");
                                ui.add(egui::Label::new(egui::RichText::new(shown).monospace().size(12.0).color(t.text_dim)).wrap_mode(egui::TextWrapMode::Extend).selectable(true));
                            }
                            Err(error) => {
                                ui.label(egui::RichText::new(format!("Не прочитать: {error}")).size(theme::SMALL).color(t.danger));
                            }
                        }
                    });
                }
                _ => {
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new("Выберите файл слева").size(theme::SMALL).color(t.text_faint));
                }
            }
        });
    });
    ui.data_mut(|d| d.insert_temp(egui::Id::new("code-selected"), selected.clone()));
}

fn empty(ui: &mut Ui, t: &Tokens) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("Код проекта").font(theme::semibold(theme::TITLE - 8.0)).color(t.text));
        ui.add_space(6.0);
        ui.label(egui::RichText::new("Откройте проект в чате — здесь появятся его файлы: просмотр без запуска и правок.").size(theme::SMALL).color(t.text_dim));
    });
}
