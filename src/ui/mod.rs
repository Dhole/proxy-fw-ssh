use crate::model::Permission;
use crate::ui::messages::{
    ReplyAcceptKey, ReplyClientName, ReplyPermission, RequestAcceptKey, RequestClientName,
    RequestPermission, RequestUi,
};
use async_channel::{Receiver, Sender};
use gtk4::{
    self as gtk, glib, prelude::*, Align, Application, ApplicationWindow, Button, Entry,
    Justification, Label,
};
use log::debug;
use std::{cell::RefCell, rc::Rc, sync::OnceLock};
use tokio::sync::oneshot;

pub mod messages;

fn win_req_permission(
    win: &ApplicationWindow,
    req: RequestPermission,
    reply_tx: oneshot::Sender<ReplyPermission>,
) {
    let reply_tx = Rc::new(RefCell::new(Some(reply_tx)));
    win.connect_close_request({
        let reply_tx = reply_tx.clone();
        move |w| {
            debug!("win.close_request");
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
        req.pk_openssh, req.action
    ));

    let btn_allow = Button::builder().label("Allow always").build();
    let btn_allow_once = Button::builder().label("Allow once").build();
    let btn_deny = Button::builder().label("Deny always").build();

    btn_allow.connect_clicked({
        let win = win.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
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

fn win_req_client_name(
    win: &ApplicationWindow,
    req: RequestClientName,
    reply_tx: oneshot::Sender<ReplyClientName>,
) {
    let reply_tx = Rc::new(RefCell::new(Some(reply_tx)));
    win.connect_close_request({
        let reply_tx = reply_tx.clone();
        move |w| {
            if let Some(tx) = reply_tx.take() {
                tx.send(ReplyClientName { name: None }).expect("send once");
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
        concat!("New client with key\n", "<b>{}</b>\n"),
        req.pk_openssh
    ));

    let label_name = Label::builder().label("Name:").build();
    let text_name = Entry::builder().build();
    let btn_save = Button::builder().label("Save").build();
    btn_save.set_sensitive(false);

    text_name.connect_changed({
        let btn_save = btn_save.clone();
        move |text| {
            if text.text_length() == 0 {
                btn_save.set_sensitive(false);
            } else {
                btn_save.set_sensitive(true);
            }
        }
    });
    btn_save.connect_clicked({
        let win = win.clone();
        let text_name = text_name.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
            let tx = reply_tx.take().expect("first take");
            tx.send(ReplyClientName {
                name: Some(text_name.text().to_string()),
            })
            .expect("send once");
            win.close();
        }
    });

    grid.attach(&label, 0, 0, 3, 1);
    grid.attach(&label_name, 0, 1, 1, 1);
    grid.attach(&text_name, 1, 1, 1, 1);
    grid.attach(&btn_save, 2, 1, 1, 1);
}

fn win_req_accept_key(
    win: &ApplicationWindow,
    req: RequestAcceptKey,
    reply_tx: oneshot::Sender<ReplyAcceptKey>,
) {
    let reply_tx = Rc::new(RefCell::new(Some(reply_tx)));
    win.connect_close_request({
        let reply_tx = reply_tx.clone();
        move |w| {
            debug!("win.close_request");
            if let Some(tx) = reply_tx.take() {
                tx.send(ReplyAcceptKey { accept: false })
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
        concat!(
            "Accept connection to host\n",
            "<b>{}</b>\n",
            "with key fingerprint\n",
            "<b>{}</b>?"
        ),
        req.host,
        req.key.fingerprint(ssh_key::HashAlg::Sha256)
    ));

    let btn_yes = Button::builder().label("Yes").build();
    let btn_no = Button::builder().label("No").build();

    btn_yes.connect_clicked({
        let win = win.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
            let tx = reply_tx.take().expect("first take");
            tx.send(ReplyAcceptKey { accept: true }).expect("send once");
            win.close();
        }
    });
    btn_no.connect_clicked({
        let win = win.clone();
        let reply_tx = reply_tx.clone();
        move |button| {
            let tx = reply_tx.take().expect("first take");
            tx.send(ReplyAcceptKey { accept: false })
                .expect("send once");
            win.close();
        }
    });

    grid.attach(&label, 0, 0, 2, 1);
    grid.attach(&btn_yes, 0, 1, 1, 1);
    grid.attach(&btn_no, 1, 1, 1, 1);
}

pub fn main_ui(req_rx: Receiver<RequestUi>) -> glib::ExitCode {
    let app = Application::builder().build();
    // Keep the "app" running even if there are no GTK windows
    let _app_hold = app.hold();

    let req_rx = Rc::new(RefCell::new(Some(req_rx)));
    app.connect_startup({
        let app = app.clone();
        move |_| {
            debug!("app.connect_startup");

            let app = app.clone();
            // Receive wakeups on the GTK main loop via glib::spawn_future_local
            let req_rx = req_rx.take().unwrap();
            glib::spawn_future_local(async move {
                while let Ok(req) = req_rx.recv().await {
                    let win = ApplicationWindow::builder()
                        .application(&app)
                        .title("proxy-fw-ssh")
                        .default_width(32)
                        .default_height(32)
                        .build();
                    match req {
                        RequestUi::Permission(req, reply_tx) => {
                            win_req_permission(&win, req, reply_tx)
                        }
                        RequestUi::ClientName(req, reply_tx) => {
                            win_req_client_name(&win, req, reply_tx)
                        }
                        RequestUi::AcceptKey(req, reply_tx) => {
                            win_req_accept_key(&win, req, reply_tx)
                        }
                    }

                    win.present();
                }
            });
        }
    });

    app.connect_activate(move |_| {
        debug!("app.connect_activate");
    });

    app.run_with_args::<glib::GString>(&[])
}
