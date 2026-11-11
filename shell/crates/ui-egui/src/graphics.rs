//! Вкладка «Графика»: макеты и векторная графика + спецификация прямо на холсте.
//! Открываем SVG (превью и список элементов) и файлы .fig/.figcraft (пока только метаданные).
//! Снизу — строка задания: выбираем элемент и пишем, что он должен делать; собираем спеку.

use crate::theme::{self, Tokens};
use crate::CraftApp;
use craft_anything_engine::{CallOptions, Caller, Consent};
use egui::{RichText, Ui};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
struct Mockup {
    path: Option<PathBuf>,
    kind: Option<String>,
    svg: Option<Vec<u8>>,
    elements: Vec<String>,
    selected: Option<String>,
    draft: String,
    spec: Vec<(String, String)>,
    query: String,
    found: Vec<String>,
}

impl Mockup {
    fn reset(&mut self) {
        self.path = None;
        self.kind = None;
        self.svg = None;
        self.elements.clear();
        self.selected = None;
        self.spec.clear();
        self.draft.clear();
        self.found.clear();
    }
}

/// Сохранить строки спецификации в память LSRE (эмбеддинги посчитает движок).
fn remember_spec(app: &CraftApp, mockup: &Mockup) -> Result<usize, String> {
    let file = mockup.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
    let mut saved = 0;
    for (element, intent) in &mockup.spec {
        let params = json!({
            "text": format!("Макет {file}: {element} — {intent}"),
            "kind": "decision",
            "tags": "mockup,ui",
            "bank": "mockup",
        });
        app.engine.call("lsre_remember", params, CallOptions::new(Caller::Ui).with_consent(Consent::Granted)).map_err(|e| e.message)?;
        saved += 1;
    }
    Ok(saved)
}

/// Семантический поиск по сохранённым спецификациям (гибрид BM25 + косинус в движке).
fn search_specs(app: &CraftApp, query: &str) -> Result<Vec<String>, String> {
    let params = json!({ "query": query, "bank": "mockup", "limit": 5 });
    let out = app.engine.call("lsre_recall", params, CallOptions::new(Caller::Ui).with_consent(Consent::Granted)).map_err(|e| e.message)?;
    let value = out.to_json();
    let result = value.get("result").cloned().unwrap_or(value);
    let mut rows = Vec::new();
    if let Some(list) = result.get("results").and_then(|v| v.as_array()) {
        for item in list {
            match item {
                serde_json::Value::String(text) => rows.push(text.clone()),
                other => {
                    if let Some(text) = other.get("text").and_then(|v| v.as_str()) {
                        rows.push(text.to_string());
                    }
                }
            }
        }
    }
    if rows.is_empty() {
        return Err("ничего не найдено (или движок ещё не видел спеку)".into());
    }
    Ok(rows)
}

fn extract_elements(svg: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = svg;
    while let Some(index) = rest.find("id=\"") {
        let after = &rest[index + 4..];
        match after.find('"') {
            Some(end) => {
                let id = after[..end].trim();
                if !id.is_empty() && id.len() < 80 && !out.iter().any(|e| e == &format!("id: {id}")) {
                    out.push(format!("id: {id}"));
                }
                rest = &after[end..];
            }
            None => break,
        }
        if out.len() >= 300 {
            return out;
        }
    }
    let mut rest = svg;
    while let Some(index) = rest.find("<text") {
        let after = &rest[index..];
        if let Some(gt) = after.find('>') {
            let tail = &after[gt + 1..];
            if let Some(close) = tail.find("</text>") {
                let text = tail[..close].trim();
                if !text.is_empty() && text.len() < 120 && !out.iter().any(|e| e == &format!("text: {text}")) {
                    out.push(format!("text: {text}"));
                }
            }
        }
        rest = &after[1..];
        if out.len() >= 400 {
            break;
        }
    }
    out
}

fn open_dialog(extensions: &[&str]) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new();
    for ext in extensions {
        dialog = dialog.add_filter(ext.to_uppercase(), &[*ext]);
    }
    dialog.pick_file()
}

fn load(mockup: &mut Mockup, path: PathBuf) -> Result<(), String> {
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > 64 * 1024 * 1024 {
        return Err("файл больше 64 МБ".into());
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    mockup.reset();
    mockup.path = Some(path.clone());
    match ext.as_str() {
        "svg" => {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("чтение: {e}"))?;
            mockup.elements = extract_elements(&text);
            mockup.svg = Some(text.into_bytes());
            mockup.kind = Some("svg".into());
        }
        "fig" | "figcraft" => {
            mockup.kind = Some(ext.clone());
        }
        other => return Err(format!("формат .{other} не поддержан (svg, fig, figcraft)")),
    }
    Ok(())
}

fn spec_path(mockup: &Mockup) -> Option<PathBuf> {
    let path = mockup.path.as_ref()?;
    Some(path.with_extension("spec.md"))
}

fn save_spec(mockup: &Mockup) -> Result<PathBuf, String> {
    let target = spec_path(mockup).ok_or("нет открытого файла")?;
    let name = mockup.path.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut text = format!("# Спецификация: {name}\n\n");
    for (element, intent) in &mockup.spec {
        if element == "-" {
            text.push_str(&format!("- {intent}\n"));
        } else {
            text.push_str(&format!("- **{element}** — {intent}\n"));
        }
    }
    std::fs::write(&target, text).map_err(|e| format!("{}: {e}", target.display()))?;
    Ok(target)
}

pub fn show(app: &mut CraftApp, ui: &mut Ui) {
    let t = Tokens::get(ui.ctx());
    let mut mockup: Mockup = ui.data(|d| d.get_temp(egui::Id::new("mockup"))).unwrap_or_default();
    if mockup.path.is_none()
        && let Ok(initial) = std::env::var("LSRE_MOCKUP_FILE")
    {
        let path = PathBuf::from(initial);
        if path.is_file() {
            let _ = load(&mut mockup, path);
        }
    }

    ui.horizontal(|ui| {
        ui.add_space(4.0);
        ui.label(RichText::new("Графика: макеты").font(theme::semibold(theme::TITLE - 8.0)).color(t.text));
        ui.add_space(10.0);
        if ui.button("Открыть SVG…").clicked() {
            if let Some(path) = open_dialog(&["svg"]) {
                if let Err(error) = load(&mut mockup, path) {
                    app.toast(error, true);
                }
            }
        }
        if ui.button("Открыть .fig / .figcraft…").clicked() {
            if let Some(path) = open_dialog(&["fig", "figcraft"]) {
                if let Err(error) = load(&mut mockup, path) {
                    app.toast(error, true);
                }
            }
        }
        if mockup.path.is_some() && ui.button("Закрыть").clicked() {
            mockup.reset();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(6.0);
            ui.label(RichText::new("выберите элемент — опишите его снизу").size(theme::CAPTION).color(t.text_faint));
        });
    });
    ui.add_space(6.0);

    // Тело: слева холст/превью, справа список элементов.
    let list_w = 280.0_f32.min(ui.available_width() * 0.4);
    let body_h = (ui.available_height() - 170.0).max(160.0);
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width() - list_w - 10.0, body_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| canvas(&mockup, &t, ui),
        );
        ui.add_space(6.0);
        ui.allocate_ui_with_layout(egui::vec2(list_w, body_h), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.label(RichText::new(format!("Элементы ({})", mockup.elements.len())).size(theme::CAPTION).color(t.text_faint));
            ui.add_space(4.0);
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for element in &mockup.elements {
                    let on = mockup.selected.as_deref() == Some(element.as_str());
                    let label = RichText::new(element).size(theme::SMALL).color(if on { t.text } else { t.text_dim });
                    if ui.add(egui::Button::new(label).selected(on).frame(false)).clicked() {
                        mockup.selected = Some(element.clone());
                    }
                }
                if mockup.elements.is_empty() {
                    ui.label(RichText::new("Откройте SVG — элементы появятся здесь").size(theme::CAPTION).color(t.text_faint));
                }
            });
        });
    });

    ui.add_space(6.0);
    ui.separator();
    // Низ: строка задания на выбранный элемент.
    ui.horizontal(|ui| {
        let target = mockup.selected.clone().unwrap_or_else(|| "весь макет".into());
        ui.label(RichText::new(format!("Задание для: {target}")).size(theme::CAPTION).color(t.accent_ink));
        if !mockup.spec.is_empty() && ui.small_button("Сохранить спецификацию").clicked() {
            match save_spec(&mockup) {
                Ok(path) => app.toast(format!("Спецификация: {}", path.display()), false),
                Err(error) => app.toast(error, true),
            }
        }
        if !mockup.spec.is_empty() && ui.small_button("Запомнить в LSRE").clicked() {
            match remember_spec(app, &mockup) {
                Ok(saved) => app.toast(format!("В память LSRE записано строк: {saved}"), false),
                Err(error) => app.toast(format!("Память: {error}"), true),
            }
        }
    });
    let response = ui.add(
        egui::TextEdit::multiline(&mut mockup.draft)
            .desired_rows(2)
            .hint_text("Что делает этот элемент: «кнопка Сохранить — сохраняет проект и закрывает окно»")
            .desired_width(ui.available_width()),
    );
    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter) && !i.modifiers.shift);
    if enter && !mockup.draft.trim().is_empty() {
        let element = mockup.selected.clone().unwrap_or_else(|| "-".into());
        mockup.spec.push((element, mockup.draft.trim().to_string()));
        mockup.draft.clear();
        response.request_focus();
    }
    ui.add_space(4.0);
    egui::ScrollArea::vertical().max_height(90.0).show(ui, |ui| {
        for (element, intent) in &mockup.spec {
            ui.label(
                RichText::new(format!("{element}: {intent}"))
                    .size(theme::CAPTION)
                    .color(t.text_dim),
            );
        }
    });

    // Поиск по смыслу среди сохранённых спецификаций: считает движок LSRE (эмбеддинги).
    ui.horizontal(|ui| {
        ui.label(RichText::new("Поиск по смыслу:").size(theme::CAPTION).color(t.text_faint));
        let field = ui.add(
            egui::TextEdit::singleline(&mut mockup.query)
                .hint_text("кнопка сохранения")
                .desired_width(260.0),
        );
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.button("Найти").clicked() || enter) && !mockup.query.trim().is_empty() {
            match search_specs(app, mockup.query.trim()) {
                Ok(rows) => mockup.found = rows,
                Err(error) => app.toast(error, true),
            }
        }
    });
    for line in &mockup.found {
        ui.label(RichText::new(line).size(theme::CAPTION).color(t.text_dim));
    }

    if mockup.path.is_some() && mockup.svg.is_some() && mockup.spec.is_empty() {
        // пустая спецификация — ничего не показываем, подсказка уже есть в поле ввода
    }
    ui.data_mut(|d| d.insert_temp(egui::Id::new("mockup"), mockup));
}

fn canvas(mockup: &Mockup, t: &Tokens, ui: &mut Ui) {
    egui::Frame::new()
        .fill(t.card)
        .stroke(egui::Stroke::new(1.0, t.card_border))
        .corner_radius(t.radius_lg)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            let Some(path) = &mockup.path else {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(RichText::new("Откройте SVG, .fig или .figcraft").size(theme::SMALL).color(t.text_dim));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("SVG показывается и разбирается на элементы; .fig/.figcraft — метаданные (парсер в работе).")
                            .size(theme::CAPTION)
                            .color(t.text_faint),
                    );
                });
                return;
            };
            ui.label(RichText::new(path.display().to_string()).monospace().size(theme::CAPTION).color(t.text_faint));
            ui.add_space(6.0);
            match (&mockup.kind, &mockup.svg) {
                (Some(kind), Some(bytes)) if kind == "svg" => {
                    let uri = format!("bytes://mockup-{}.svg", mockup.elements.len());
                    let image = egui::Image::from_bytes(uri, egui::load::Bytes::from(bytes.clone()))
                        .fit_to_exact_size(egui::vec2(ui.available_width().min(720.0), ui.available_height().min(520.0)));
                    ui.add(image);
                }
                (Some(kind), _) => {
                    ui.label(RichText::new(format!("Формат: {kind}")).size(theme::SMALL).color(t.text));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Это контейнер дизайн-файла. Парсер ещё не подключён: пока можно вести спецификацию по макету вручную.")
                            .size(theme::CAPTION)
                            .color(t.text_faint),
                    );
                }
                _ => {}
            }
        });
}

// (помощники не нужны: цвет берём из токенов темы)
