extern crate gtk;
extern crate gio;
extern crate pcap;
extern crate libc;
extern crate byteorder;
extern crate time;
extern crate sexp;
extern crate guile_sys;

use std::env::Args;
use std::rc::Rc;
use std::cell::RefCell;

use gio::{
    SimpleActionExt, ActionMapExt, ApplicationExt
};

use gtk::{
    WidgetExt, GtkApplicationExt
};

use std::ffi::CStr;
use std::ffi::CString;
use libc::c_void;

use guile_sys::{
    SCM, scm_c_define_gsubr, scm_from_pointer,
    scm_c_define, scm_with_guile, scm_c_primitive_load
};

mod win;
mod disctr;

use disctr::{
    DissectorTable, set_dissector, set_info,
    set_proto,
};

fn init_actions(app: &gtk::Application) {
    let quit_action = gio::SimpleAction::new("quit", None);
    {
        let app = app.clone();
        quit_action.connect_activate(move |_, _| {
            app.quit();
        });
    }


    app.add_action(&quit_action);
}

fn init_accels(app: &gtk::Application) {
    app.add_accelerator("<Ctrl>q", "app.quit", None);
}

unsafe extern "C" fn init_guile(dissector_tbl: *mut c_void) -> *mut c_void {
    let prc = set_dissector as *mut fn(SCM, SCM, SCM, SCM) -> SCM as *mut c_void;
    scm_c_define_gsubr(CStr::from_bytes_with_nul(b"set-dissector\0").unwrap().as_ptr(), 4, 0, 0, prc);

    let prc = set_proto as *mut fn(SCM, SCM) -> SCM as *mut c_void;
    scm_c_define_gsubr(CStr::from_bytes_with_nul(b"set-proto\0").unwrap().as_ptr(), 2, 0, 0, prc);

    let prc = set_info as *mut fn(SCM, SCM) -> SCM as *mut c_void;
    scm_c_define_gsubr(CStr::from_bytes_with_nul(b"set-info\0").unwrap().as_ptr(), 2, 0, 0, prc);

    let dsctr_tbl = scm_from_pointer(dissector_tbl, None);
    scm_c_define(CStr::from_bytes_with_nul(b"dissector-table\0").unwrap().as_ptr(), dsctr_tbl);

    dissector_tbl
}


fn run(args: Args) {
    match gtk::Application::new("com.github.koji-m.wire_shake", gio::APPLICATION_HANDLES_OPEN) {
        Ok(app) => {
            {
                app.connect_startup(move |app| {
                    init_actions(app);
                    init_accels(app);
                });
            }

            let mut disct_tbl = DissectorTable::new();
            unsafe {
                scm_with_guile(Some(init_guile), &mut disct_tbl as *mut _ as *mut c_void);
                scm_c_primitive_load(CString::new("src/dissector.scm").unwrap().as_ptr());
            }

            let disct_tbl = Rc::new(RefCell::new(disct_tbl));
            {
                app.connect_activate(move |app| {
                    let w = win::create(app, disct_tbl.clone());
                    w.show_all();
                });
            }


            let args: Vec<String> = args.collect();
            let argv: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();

            app.run(argv.as_slice());
        },

        Err(_) => {
            println!("Application startup error");
        }
    };
}

fn main() {
    run(std::env::args());
}

