//! Архитектурная карта: читаемая иерархия узлов и связей с нодовой сцепкой.
//! Данные — JSON в каталоге настроек (`architecture.json`), по умолчанию — карта самого LSRE.

use crate::theme::{self, Tokens};
use crate::CraftApp;
use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Vec2};
use serde::{Deserialize, Serialize};

const NODE_W: f32 = 220.0;
const NODE_H: f32 = 78.0;
/// Слои идут сверху вниз: родители выше, дети ниже.
const ROW_STEP: f32 = 188.0;
const COL_STEP: f32 = 268.0;

#[derive(Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub layer: usize,
    #[serde(default)]
    pub x: f32,
    #[serde(default)]
    pub y: f32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Map {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub layers: Vec<String>,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

impl Map {
    /// Карта самого LSRE: вход → оболочка → диспетчер → инструменты → данные.
    pub fn lsre() -> Self {
        let layers = vec![
            "Вход".to_string(),
            "Оболочка".to_string(),
            "Диспетчер".to_string(),
            "Движок LSRE".to_string(),
            "Данные".to_string(),
        ];
        let mut nodes = vec![
            node("input", "Файл или проект", "Путь, папка, процесс", 0),
            node("ui", "LSRE UI (egui)", "Экраны, чат, карточки", 1),
            node("cli", "CLI / MCP", "Тот же движок снаружи", 1),
            node("registry", "Реестр инструментов", "321 инструмент, схемы", 2),
            node("plugin", "Плагин lsre (MCP)", "24 наших инструмента", 2),
            node("triage", "Триаж", "PE/ELF/APK/PDF, энтропия", 3),
            node("memory", "Память", "Факты, наблюдения, граф", 3),
            node("embed", "Эмбеддинги", "e5-small 384d, офлайн", 3),
            node("ghidra", "Ghidra", "Декомпиляция по запросу", 3),
            node("frida", "Frida", "Рантайм, перехваты", 3),
            node("yara", "YARA-X", "Правила, скан", 3),
            node("sqlite", "SQLite", "WAL, FTS5, векторы", 4),
            node("model", "Модель e5", "112,6 МБ, int8", 4),
            node("cache", "Кэш sha256", "Повторный разбор 0 мс", 4),
        ];
        let edges = vec![
            edge("input", "ui"),
            edge("ui", "registry"),
            edge("cli", "registry"),
            edge("registry", "plugin"),
            edge("plugin", "triage"),
            edge("plugin", "memory"),
            edge("plugin", "embed"),
            edge("plugin", "ghidra"),
            edge("plugin", "frida"),
            edge("plugin", "yara"),
            edge("triage", "cache"),
            edge("memory", "sqlite"),
            edge("embed", "model"),
            edge("triage", "sqlite"),
        ];
        let mut map = Map { title: "Архитектура LSRE".into(), layers, nodes: std::mem::take(&mut nodes), edges };
        map.layout();
        map
    }

    /// Разложить по слоям сверху вниз: слой — строка, узлы внутри слоя — слева направо.
    pub fn layout(&mut self) {
        let mut per_layer: Vec<usize> = vec![0; self.layers.len().max(1)];
        for node in &mut self.nodes {
            let layer = node.layer.min(per_layer.len().saturating_sub(1));
            let column = per_layer[layer];
            per_layer[layer] += 1;
            node.x = 132.0 + column as f32 * COL_STEP;
            node.y = 72.0 + layer as f32 * ROW_STEP;
        }
    }

    fn find(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }
}

fn node(id: &str, title: &str, note: &str, layer: usize) -> Node {
    Node { id: id.into(), title: title.into(), note: note.into(), layer, x: 0.0, y: 0.0 }
}

fn edge(from: &str, to: &str) -> Edge {
    Edge { from: from.into(), to: to.into(), label: String::new() }
}

/// Состояние холста: живёт в памяти egui, чтобы панорама и зум не сбрасывались.
#[derive(Clone)]
pub struct Canvas {
    pub map: Map,
    pub zoom: f32,
    pub pan: Vec2,
    pub selected: Option<String>,
    pub moved: bool,
    pub initialized: bool,
}

impl Default for Canvas {
    fn default() -> Self {
        Self { map: Map::lsre(), zoom: 1.0, pan: Vec2::ZERO, selected: None, moved: false, initialized: false }
    }
}

fn canvas_id() -> egui::Id {
    egui::Id::new("lsre-architecture-canvas")
}

fn map_path() -> std::path::PathBuf {
    craft_anything_engine::settings::config_dir().join("architecture.json")
}

fn load(canvas: &mut Canvas) -> Result<(), String> {
    let path = map_path();
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let map: Map = serde_json::from_str(&text).map_err(|e| format!("JSON: {e}"))?;
    if map.nodes.is_empty() {
        return Err("в файле нет узлов".into());
    }
    canvas.map = map;
    canvas.selected = None;
    Ok(())
}

fn save(canvas: &Canvas) -> Result<std::path::PathBuf, String> {
    let path = map_path();
    let text = serde_json::to_string_pretty(&canvas.map).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Экран «Архитектура».
pub fn show(app: &mut CraftApp, ui: &mut egui::Ui) {
    let t = Tokens::get(ui.ctx());
    let mut canvas = ui.data(|d| d.get_temp::<Canvas>(canvas_id())).unwrap_or_default();
    let mut toast: Option<(String, bool)> = None;

    ui.horizontal(|ui| {
        ui.add_space(4.0);
        ui.label(egui::RichText::new(&canvas.map.title).font(theme::semibold(theme::TITLE - 6.0)).color(t.text));
        ui.add_space(10.0);
        if ui.button("Разложить").clicked() {
            canvas.map.layout();
            canvas.moved = true;
        }
        if ui.button("Сброс вида").clicked() {
            canvas.zoom = 1.0;
            canvas.pan = Vec2::ZERO;
        }
        if ui.button("Сохранить").clicked() {
            match save(&canvas) {
                Ok(p) => toast = Some((format!("Сохранено: {}", p.display()), false)),
                Err(e) => toast = Some((format!("Не сохранено: {e}"), true)),
            }
        }
        if map_path().exists() && ui.button("Загрузить").clicked() {
            match load(&mut canvas) {
                Ok(()) => toast = Some(("Карта загружена".into(), false)),
                Err(e) => toast = Some((format!("Не загружено: {e}"), true)),
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if std::env::var("LSRE_ARCH_DEBUG").as_deref() == Ok("1") {
                ui.label(egui::RichText::new(format!("zoom={:.2} sel={:?} nodes={}", canvas.zoom, canvas.selected, canvas.map.nodes.len())).size(theme::CAPTION).color(t.warning));
            }
            ui.label(egui::RichText::new("колесо — зум · перетаскивание — панорама · клик по узлу — детали").size(theme::CAPTION).color(t.text_faint));
        });
    });
    ui.add_space(6.0);

    let body_w = ui.available_width();
    let panel_w = if canvas.selected.is_some() { 300.0 } else { 0.0 };
    let canvas_w = (body_w - panel_w - 16.0).max(120.0);

    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(Vec2::new(canvas_w, ui.available_height()), egui::Layout::top_down(egui::Align::Min), |ui| {
            draw_canvas(&mut canvas, &t, ui);
        });
        if canvas.selected.is_some() {
            ui.add_space(6.0);
            ui.allocate_ui_with_layout(Vec2::new((panel_w - 8.0).max(120.0), ui.available_height()), egui::Layout::top_down(egui::Align::Min), |ui| {
                draw_inspector(&mut canvas, &t, ui);
            });
        }
    });

    if let Some((text, error)) = toast {
        app.toast(&text, error);
    }
    ui.data_mut(|d| d.insert_temp(canvas_id(), canvas));
}

fn draw_canvas(canvas: &mut Canvas, t: &Tokens, ui: &mut egui::Ui) {
    let (rect, bg) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, t.radius_lg, t.canvas);
    painter.rect_stroke(rect, t.radius_lg, Stroke::new(1.0, t.separator), StrokeKind::Inside);

    // Первый показ: вписать всю карту в окно, чтобы слои не уезжали за край.
    if !canvas.initialized {
        canvas.initialized = true;
        let mut max_x = 1.0f32;
        let mut max_y = 1.0f32;
        for node in &canvas.map.nodes {
            max_x = max_x.max(node.x + NODE_W);
            max_y = max_y.max(node.y + NODE_H);
        }
        let fit_x = (rect.width() - 40.0) / max_x;
        let fit_y = (rect.height() - 40.0) / max_y;
        canvas.zoom = fit_x.min(fit_y).clamp(0.4, 1.0);
        canvas.pan = Vec2::new(8.0, 8.0);
    }

    // Зум колесом вокруг курсора, панорама перетаскиванием фона.
    if bg.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll.abs() > 0.1 {
            let anchor = bg.hover_pos().unwrap_or(rect.center());
            let before = world_at(anchor, rect, canvas);
            canvas.zoom = (canvas.zoom * (scroll * 0.0015).exp()).clamp(0.35, 2.0);
            let after = world_at(anchor, rect, canvas);
            canvas.pan += after - before;
        }
    }
    if bg.dragged() {
        canvas.pan += bg.drag_delta() / canvas.zoom;
    }

    // Сетка (точки) — читаемость и ощущение масштаба.
    let step = 28.0 * canvas.zoom;
    if step >= 9.0 {
        let origin = rect.min + canvas.pan * canvas.zoom;
        let mut x = origin.x - ((origin.x - rect.min.x) / step).floor() * step;
        while x < rect.max.x {
            let mut y = origin.y - ((origin.y - rect.min.y) / step).floor() * step;
            while y < rect.max.y {
                if rect.contains(egui::pos2(x, y)) {
                    painter.circle_filled(egui::pos2(x, y), 1.0, t.separator.gamma_multiply(0.9));
                }
                y += step;
            }
            x += step;
        }
    }

    // Заголовки слоёв: слева от строки, сверху вниз.
    for (index, name) in canvas.map.layers.iter().enumerate() {
        let y = rect.min.y + (48.0 + index as f32 * ROW_STEP + canvas.pan.y) * canvas.zoom;
        let x = rect.min.x + (16.0 + canvas.pan.x) * canvas.zoom;
        if y > rect.max.y - 10.0 || y < rect.min.y - 30.0 {
            continue;
        }
        painter.text(Pos2::new(x, y), Align2::LEFT_BOTTOM, name, FontId::proportional(theme::CAPTION * canvas.zoom.max(0.8)), t.text_faint);
    }

    // Узлы: сначала считываем взаимодействия, потом двигаем (иначе заняли бы карту дважды).
    let mut grabbed = false;
    let mut clicked: Option<String> = None;
    let mut drags: Vec<(String, Vec2)> = Vec::new();
    for node in &canvas.map.nodes {
        let nr = node_rect(node, rect, canvas);
        if !rect.intersects(nr) {
            continue;
        }
        let resp = ui.interact(nr, egui::Id::new(("arch-node", node.id.clone())), Sense::click_and_drag());
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grab);
        }
        if resp.dragged() {
            grabbed = true;
            drags.push((node.id.clone(), resp.drag_delta() / canvas.zoom));
        }
        if resp.clicked() {
            clicked = Some(node.id.clone());
        }
    }
    for (id, delta) in drags {
        if let Some(target) = canvas.map.nodes.iter_mut().find(|n| n.id == id) {
            target.x += delta.x;
            target.y += delta.y;
            canvas.moved = true;
        }
    }
    if bg.clicked() && !grabbed {
        canvas.selected = None;
    }
    if let Some(id) = clicked {
        canvas.selected = Some(id);
    }

    // Связи.
    for edge in &canvas.map.edges {
        let (Some(from), Some(to)) = (canvas.map.find(&edge.from), canvas.map.find(&edge.to)) else { continue };
        let a = node_rect(from, rect, canvas);
        let b = node_rect(to, rect, canvas);
        if !rect.intersects(a.union(b)) {
            continue;
        }
        let start = Pos2::new(a.center().x, a.max.y);
        let end = Pos2::new(b.center().x, b.min.y);
        let dy = ((end.y - start.y).abs().max(40.0)) * 0.55;
        let stroke = Stroke::new(1.4 * canvas.zoom, t.separator.gamma_multiply(1.15));
        painter.add(egui::epaint::CubicBezierShape::from_points_stroke(
            [start, Pos2::new(start.x, start.y + dy), Pos2::new(end.x, end.y - dy), end],
            false,
            Color32::TRANSPARENT,
            stroke,
        ));
        // Наконечник стрелки смотрит вниз, в дочерний узел.
        let dir = Vec2::new(0.0, 1.0);
        let size = 6.0 * canvas.zoom;
        let normal = Vec2::new(-dir.y, dir.x) * size * 0.6;
        painter.add(egui::Shape::convex_polygon(
            vec![end, end - dir * size + normal, end - dir * size - normal],
            stroke.color,
            Stroke::NONE,
        ));
    }

    // Сами карточки.
    for node in &canvas.map.nodes {
        let nr = node_rect(node, rect, canvas);
        if !rect.intersects(nr) {
            continue;
        }
        let selected = canvas.selected.as_deref() == Some(node.id.as_str());
        let fill = if selected { t.raised } else { t.card };
        painter.rect_filled(nr, t.radius, fill);
        painter.rect_stroke(nr, t.radius, Stroke::new(if selected { 1.6 } else { 1.0 }, if selected { t.accent } else { t.card_border }), StrokeKind::Inside);
        // Цветная полоса слоя.
        let r = t.radius.round() as u8;
        let stripe = Rect::from_min_max(nr.min, Pos2::new(nr.min.x + 4.0, nr.max.y));
        painter.rect_filled(stripe, egui::CornerRadius { nw: r, sw: r, ne: 0, se: 0 }, layer_color(node.layer, t));
        let pad = 14.0 * canvas.zoom;
        let title_font = FontId::proportional((theme::SMALL * canvas.zoom).clamp(8.0, 20.0));
        let note_font = FontId::proportional((theme::CAPTION * canvas.zoom).clamp(7.0, 16.0));
        painter.text(Pos2::new(nr.min.x + pad, nr.min.y + 12.0 * canvas.zoom), Align2::LEFT_TOP, &node.title, title_font, t.text);
        painter.text(Pos2::new(nr.min.x + pad, nr.min.y + 40.0 * canvas.zoom), Align2::LEFT_TOP, &node.note, note_font, t.text_dim);
    }

    if canvas.map.nodes.is_empty() {
        painter.text(rect.center(), Align2::CENTER_CENTER, "Карта пуста: загрузите JSON или нажмите «Разложить»", FontId::proportional(theme::SMALL), t.text_faint);
    }
}

fn draw_inspector(canvas: &mut Canvas, t: &Tokens, ui: &mut egui::Ui) {
    let Some(id) = canvas.selected.clone() else { return };
    let Some(node) = canvas.map.find(&id).cloned() else { return };
    egui::Frame::new()
        .fill(t.card)
        .stroke(Stroke::new(1.0, t.card_border))
        .corner_radius(t.radius_lg)
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(240.0);
            ui.label(egui::RichText::new(&node.title).font(theme::semibold(theme::BODY)).color(t.text));
            let layer = canvas.map.layers.get(node.layer).cloned().unwrap_or_default();
            ui.label(egui::RichText::new(format!("Слой: {layer}")).size(theme::CAPTION).color(t.text_faint));
            ui.add_space(6.0);
            if !node.note.is_empty() {
                ui.label(egui::RichText::new(&node.note).size(theme::SMALL).color(t.text_dim));
            }
            ui.add_space(10.0);
            let incoming: Vec<String> = canvas.map.edges.iter().filter(|e| e.to == id).map(|e| e.from.clone()).collect();
            let outgoing: Vec<String> = canvas.map.edges.iter().filter(|e| e.from == id).map(|e| e.to.clone()).collect();
            if !incoming.is_empty() {
                ui.label(egui::RichText::new("Входит от").size(theme::CAPTION).color(t.text_faint));
                for source in &incoming {
                    if let Some(n) = canvas.map.find(source) {
                        if ui.link(n.title.clone()).clicked() {
                            canvas.selected = Some(n.id.clone());
                        }
                    }
                }
                ui.add_space(6.0);
            }
            if !outgoing.is_empty() {
                ui.label(egui::RichText::new("Ведёт к").size(theme::CAPTION).color(t.text_faint));
                for target in &outgoing {
                    if let Some(n) = canvas.map.find(target) {
                        if ui.link(n.title.clone()).clicked() {
                            canvas.selected = Some(n.id.clone());
                        }
                    }
                }
            }
            ui.add_space(10.0);
            if ui.button("Закрыть").clicked() {
                canvas.selected = None;
            }
        });
}

fn world_at(screen: Pos2, rect: Rect, canvas: &Canvas) -> Vec2 {
    (screen - rect.min) / canvas.zoom - canvas.pan
}

fn node_rect(node: &Node, rect: Rect, canvas: &Canvas) -> Rect {
    let min = rect.min + (Vec2::new(node.x, node.y) + canvas.pan) * canvas.zoom;
    Rect::from_min_size(min, Vec2::new(NODE_W, NODE_H) * canvas.zoom)
}

fn layer_color(layer: usize, t: &Tokens) -> Color32 {
    match layer % 5 {
        0 => t.text_faint,
        1 => t.accent,
        2 => t.warning,
        3 => t.success,
        _ => t.accent_ink,
    }
}
