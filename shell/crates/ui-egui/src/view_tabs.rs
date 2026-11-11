//! Лента переключения режимов над экраном: Чат · Код · Архитектура.

use crate::state::Screen;
use crate::theme::{self, Tokens};
use crate::CraftApp;
use egui::Ui;

/// Активна ли лента «Чат» (обычный чат и проект).
fn chat_active(screen: Screen) -> bool {
    matches!(screen, Screen::Home | Screen::Project | Screen::Ask)
}

/// Нарисовать ленту и переключить экран по клику.
pub fn ribbon(app: &mut CraftApp, ui: &mut Ui) {
    let t = Tokens::get(ui.ctx());
    ui.horizontal(|ui| {
        ui.add_space(6.0);
        if pill(ui, "Чат", chat_active(app.state.screen), &t).clicked() {
            app.state.screen = if app.workspace.is_some() { Screen::Project } else { Screen::Home };
        }
        if pill(ui, "Код", app.state.screen == Screen::Code, &t).clicked() {
            app.state.screen = Screen::Code;
        }
        if pill(ui, "Архитектура", app.state.screen == Screen::Architecture, &t).clicked() {
            app.state.screen = Screen::Architecture;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("режим работы").size(theme::CAPTION).color(t.text_faint));
        });
    });
    ui.add_space(4.0);
    ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, t.separator));
    ui.add_space(4.0);
}

fn pill(ui: &mut Ui, text: &str, on: bool, t: &Tokens) -> egui::Response {
    let label = egui::RichText::new(text).size(theme::SMALL).color(if on { t.text } else { t.text_dim });
    let resp = ui.add(egui::Button::new(label).fill(if on { t.pressed } else { egui::Color32::TRANSPARENT }).stroke(egui::Stroke::new(1.0, if on { t.accent.gamma_multiply(0.7) } else { t.separator })).corner_radius(t.radius));
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}
