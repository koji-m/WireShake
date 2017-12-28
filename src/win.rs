extern crate gtk;
extern crate gio;
extern crate pcap;

use std::path::Path;
use std::thread;
use std::sync::mpsc;

use std::rc::Rc;
use std::cell::RefCell;

use std::ffi::CString;
use guile_sys::{
    scm_variable_ref, scm_c_lookup,
};

use gio::{
    SimpleActionExt, ActionMapExt
};

use gtk::{
    WindowExt, ComboBoxTextExt,
    ListStoreExt, TreeModelExt,
    ListStoreExtManual, TreeViewExt,
    TreeStoreExt, TreeStoreExtManual,
    TreeSelectionExt, Cast
};


use time;
use sexp;
use sexp::{Sexp, Atom};

use disctr::{
    PacketInfo, dissect, DissectorTable
};

const NUMBER_COLUMN: u32 = 0;
const TIME_COLUMN: u32 = 1;
const SRC_COLUMN: u32 = 2;
const DST_COLUMN: u32 = 3;
const PROTO_COLUMN: u32 = 4;
const LEN_COLUMN: u32 = 5;
const INFO_COLUMN: u32 = 6;
const DATA_COLUMN: u32 = 7;

const DETAIL_COLUMN: u32 = 0;

enum Ctrl {
    StartCapture(pcap::Capture<pcap::Active>),
    StopCapture,
    CaptureStarted,
    CaptureStopped,
}

fn string_to_dev(s: String) -> Option<pcap::Capture<pcap::Inactive>> {
    if let Ok(mut l) = pcap::Device::list() {
        if let Some(i) = l.iter().position(|ref d| d.name == s) {
            if let Ok(cap) = pcap::Capture::from_device(l.remove(i)) {
                return Some(cap.promisc(true).timeout(300));
            }
        }
    }
    return None;
}

fn output_packet(tree: String, pinfo: PacketInfo, store: gtk::TreeModel) {
    let store = store.downcast::<gtk::ListStore>().ok().unwrap();
    let itr = store.append();

    let time = time::strftime("%F %T", &time::at(pinfo.time)).unwrap();

    store.set(&itr,
              &[NUMBER_COLUMN, TIME_COLUMN, SRC_COLUMN, DST_COLUMN, PROTO_COLUMN,
                LEN_COLUMN, INFO_COLUMN, DATA_COLUMN],
              &[&pinfo.num, &time, &pinfo.net_src, &pinfo.net_dst, &pinfo.proto,
                &pinfo.len, &pinfo.info, &tree]);
}

fn init_action(win: &gtk::ApplicationWindow, builder: &gtk::Builder, disct_tbl: Rc<RefCell<DissectorTable>>) {
    use self::Ctrl::{StartCapture, StopCapture, CaptureStarted, CaptureStopped};

    let start_capture_action = gio::SimpleAction::new("start-capture", None);
    let stop_capture_action = gio::SimpleAction::new("stop-capture", None);
    stop_capture_action.set_enabled(false);

    let (main_tx, cap_rx) = mpsc::channel();
    let (start_cap_tx, start_main_rx) = mpsc::channel();
    let (stop_cap_tx, stop_main_rx) = mpsc::channel();

    {
        let lst_store: gtk::ListStore = builder.get_object("list-store").unwrap();
        let stop_capture_action = stop_capture_action.clone();
        let if_combo: gtk::ComboBoxText = builder.get_object("if-combobox").unwrap();
        let main_tx = mpsc::Sender::clone(&main_tx);
        start_capture_action.connect_activate(move |act, _| {
            lst_store.clear();
            if let Some(if_name) = if_combo.get_active_text() {
                if let Ok(cap) = string_to_dev(if_name).unwrap().open() {
                    main_tx.send(StartCapture(cap)).unwrap();

                    if let Ok(CaptureStarted) = start_main_rx.recv() {
                        act.set_enabled(false);
                        stop_capture_action.set_enabled(true);
                    }
                }
            }
        });
    }

    {
        let start_capture_action = start_capture_action.clone();
        stop_capture_action.connect_activate(move |act, _| {
            main_tx.send(StopCapture).unwrap();
            if let Ok(CaptureStopped) = stop_main_rx.recv() {
                act.set_enabled(false);
                start_capture_action.set_enabled(true);
            }
        });
    }

    let (pkt_tx, pkt_rx) = mpsc::channel();

    thread::spawn(move || {
        let mut n: u32;
        while let Ok(msg) = cap_rx.recv() {
            if let StartCapture(mut cap) = msg {
                n= 1;
                start_cap_tx.send(CaptureStarted).unwrap();
                loop {
                    if let Ok(pkt) = cap.next() {
                        pkt_tx.send((n, pkt.header.clone(), pkt.data.to_vec())).unwrap();
                        n+=1;
                        if let Ok(StopCapture) = cap_rx.try_recv() {
                            break;
                        }
                    } else {
                        if let Ok(StopCapture) = cap_rx.try_recv() {
                            break;
                        }
                    }
                }
                stop_cap_tx.send(CaptureStopped).unwrap();
            }
        }
    });

    let lst_v: gtk::TreeView = builder.get_object("list_view").unwrap();
    let store = lst_v.get_model().unwrap();

    let write_proc;
    unsafe {
        write_proc = scm_variable_ref(scm_c_lookup(CString::new("write").unwrap().as_ptr()));
    }

    gtk::timeout_add(300, move || {
        while let Ok((n, hdr, data)) = pkt_rx.try_recv() {
            let (tree, pinfo) = dissect(n, hdr, data, disct_tbl.clone(), write_proc);
            output_packet(tree, pinfo, store.clone());
        }
        gtk::Continue(true)
    });

    win.add_action(&start_capture_action);
    win.add_action(&stop_capture_action);
}

fn parse_lbl_val(sxp: &Sexp) -> String {
    if let &Sexp::List(ref kv_lst) = sxp {
        if let &Sexp::Atom(ref k) = &kv_lst[0] {
            if let &Atom::S(ref lbl_str) = k {
                if let Sexp::Atom(ref v) = kv_lst[1] {
                    if let &Atom::S(ref val_str) = v {
                        return format!("{}: {}", lbl_str, val_str);
                    }
                }
            }
        }
    }
    String::from("** Parse Error **")
}

fn set_detail_tree(sxp: &Sexp, store: gtk::TreeStore, parent_itr: Option<&gtk::TreeIter>) {

    if let &Sexp::List(ref lst) = sxp {
        if lst.len() != 3 { return; }
        let itr = store.append(parent_itr);
        let disp_str = parse_lbl_val(&lst[0]);
        store.set(&itr, &[DETAIL_COLUMN], &[&disp_str]);

        set_detail_tree(&lst[1], store.clone(), Some(&itr));

        set_detail_tree(&lst[2], store, parent_itr);
    }
}

fn set_detail_pane(store: gtk::TreeStore, tree: String) {
    store.clear();

    match sexp::parse(&tree) {
        Ok(sxp) => set_detail_tree(&sxp, store, None),
        Err(e) => println!("Error: {}", e),
    }
    
}

fn init_list_view(builder: &gtk::Builder) {
    let select: gtk::TreeSelection = builder.get_object("selection").unwrap();

    let dtl_store: gtk::TreeStore = builder.get_object("detail-store").unwrap();
    select.connect_changed(move |slct| {
        if let Some((model, itr)) = slct.get_selected() {
            let data = model.get_value(&itr, DATA_COLUMN as i32);
            if let Some(tree) = data.get::<String>() {
                set_detail_pane(dtl_store.clone(), tree);
            }
        }
    });
}

pub fn create(app: &gtk::Application, disct_tbl: Rc<RefCell<DissectorTable>>) -> gtk::ApplicationWindow {
    let builder = gtk::Builder::new_from_file(Path::new("/usr/share/wire_shake/ui/win.ui"));
    let win: gtk::ApplicationWindow = builder.get_object("window").unwrap();
    win.set_application(Some(app));

    if let Ok(if_list) = pcap::Device::list() {
        let if_combo: gtk::ComboBoxText = builder.get_object("if-combobox").unwrap();
        if_list.iter().for_each(|d| if_combo.append(None, &d.name));
    }

    init_list_view(&builder);

    init_action(&win, &builder, disct_tbl);

    win
}

