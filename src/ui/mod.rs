use crate::model::Permission;
use crate::ui::messages::{ReplyPermission, RequestPermission, UiRequest};
use async_channel::{Receiver, Sender};
use gtk4::{
    self as gtk, glib, prelude::*, Align, Application, ApplicationWindow, Button, Justification,
    Label,
};
use std::{cell::RefCell, rc::Rc, sync::OnceLock};

pub mod messages;

fn win_req_permission(win: &ApplicationWindow, r: RequestPermission) {
    let reply_tx = Rc::new(RefCell::new(Some(r.reply_tx)));
    win.connect_close_request({
        let reply_tx = reply_tx.clone();
        move |w| {
            println!("DBG close request");
            if let Some(tx) = reply_tx.take() {
                tx.send(ReplyPermission {
                    now: false,
                    future: Permission::Ask,
                })
                .expect("send once");
            }
            w.set_visible(false);
            glib::Propagation::Stop
        }
    });
    let grid = gtk::Grid::builder()
        .margin_start(6)
        .margin_end(6)
        .margin_top(6)
        .margin_bottom(6)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .row_spacing(6)
        .column_spacing(6)
        .build();
    win.set_child(Some(&grid));
    let label = Label::builder().justify(Justification::Center).build();
    label.set_markup(&format!(
        concat!("Allow\n", "<b>{}</b>\n", "to {}?"),
        r.pk_openssh, r.action
    ));

    let btn_allow = Button::builder().label("Allow always").build();
    let btn_allow_once = Button::builder().label("Allow once").build();
    let btn_deny = Button::builder().label("Deny always").build();

    btn_allow.connect_clicked({
        let win = win.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
            println!("DBG allow always");
            let tx = reply_tx.take().expect("first take");
            tx.send(ReplyPermission {
                now: true,
                future: Permission::Yes,
            })
            .expect("send once");
            win.close();
        }
    });
    btn_allow_once.connect_clicked({
        let win = win.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
            println!("DBG allow once");
            let tx = reply_tx.take().expect("first take");
            tx.send(ReplyPermission {
                now: true,
                future: Permission::Ask,
            })
            .expect("send once");
            win.close();
        }
    });
    btn_deny.connect_clicked({
        let win = win.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
            println!("DBG deny always");
            let tx = reply_tx.take().expect("first take");
            tx.send(ReplyPermission {
                now: false,
                future: Permission::No,
            })
            .expect("send once");
            win.close();
        }
    });

    grid.attach(&label, 0, 0, 3, 1);
    grid.attach(&btn_allow, 0, 1, 1, 1);
    grid.attach(&btn_allow_once, 1, 1, 1, 1);
    grid.attach(&btn_deny, 2, 1, 1, 1);
}

pub fn main_ui(req_rx: Receiver<UiRequest>) -> glib::ExitCode {
    let app = Application::builder().build();
    // Keep the "app" running even if there are no GTK windows
    let _app_hold = app.hold();

    let req_rx = Rc::new(RefCell::new(Some(req_rx)));
    app.connect_startup({
        // let window_slot = window_slot.clone();
        // let win = win.clone();
        // let wake_rx = wake_rx;
        let app = app.clone();
        move |_| {
            println!("DBG connect_startup");
            // let window_slot = window_slot.clone();
            // let win = win.clone();

            let app = app.clone();
            // Receive wakeups on the GTK main loop via glib::spawn_future_local
            let req_rx = req_rx.take().unwrap();
            // let wake_rx = wake_rx.clone();
            glib::spawn_future_local(async move {
                while let Ok(req) = req_rx.recv().await {
                    let win = ApplicationWindow::builder()
                        .application(&app)
                        .title("proxy-fw-ssh")
                        .default_width(32)
                        .default_height(32)
                        .build();
                    match req {
                        UiRequest::Permission(r) => {
                            win_req_permission(&win, r);
                        }
                    }

                    win.present();
                }
            });
        }
    });

    app.connect_activate(move |_| {
        println!("DBG connect_activate");
        // win.present();
    });

    app.run_with_args::<glib::GString>(&[])
}
