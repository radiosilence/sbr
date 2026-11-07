//! Network path changes (Network.framework's path monitor) and memory
//! pressure (a dispatch source), reached through their C APIs.

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_ulong, c_void};
use std::rc::Rc;

use block2::{DynBlock, RcBlock};

type Object = *mut c_void;

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_path_monitor_create() -> Object;
    fn nw_path_monitor_set_queue(monitor: Object, queue: Object);
    fn nw_path_monitor_set_update_handler(monitor: Object, handler: &DynBlock<dyn Fn(Object)>);
    fn nw_path_monitor_start(monitor: Object);
    fn nw_path_monitor_cancel(monitor: Object);
    fn nw_path_get_status(path: Object) -> i32;
    fn nw_path_enumerate_interfaces(path: Object, enumerator: &DynBlock<dyn Fn(Object) -> u8>);
    fn nw_interface_get_type(interface: Object) -> i32;
    fn nw_interface_get_name(interface: Object) -> *const c_char;
    fn nw_release(object: Object);
}

unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attr: Object) -> Object;
    fn dispatch_get_global_queue(identifier: isize, flags: usize) -> Object;
    fn dispatch_source_create(kind: *const c_void, handle: usize, mask: c_ulong, queue: Object) -> Object;
    fn dispatch_source_set_event_handler_f(source: Object, handler: unsafe extern "C" fn(*mut c_void));
    fn dispatch_source_get_data(source: Object) -> c_ulong;
    fn dispatch_source_cancel(source: Object);
    fn dispatch_set_context(object: Object, context: *mut c_void);
    fn dispatch_set_finalizer_f(object: Object, finalizer: unsafe extern "C" fn(*mut c_void));
    fn dispatch_resume(object: Object);
    fn dispatch_release(object: Object);
    static _dispatch_source_type_memorypressure: c_void;
}

const NW_PATH_STATUS_SATISFIED: i32 = 1;
const NW_INTERFACE_TYPE_OTHER: i32 = 0;
const DISPATCH_MEMORYPRESSURE_WARN: c_ulong = 0x2;
const DISPATCH_MEMORYPRESSURE_CRITICAL: c_ulong = 0x4;

/// One report from the path monitor.
pub struct Path {
    pub satisfied: bool,
    /// Names of the physical interfaces, best first. Our own utun shows up
    /// as `other` and is left out.
    pub interfaces: Vec<String>,
}

/// Follows the default network path on a serial queue of its own until
/// dropped.
pub struct PathMonitor {
    monitor: Object,
    queue: Object,
}

// SAFETY: Network.framework objects may be used and released from any thread.
unsafe impl Send for PathMonitor {}

impl PathMonitor {
    pub fn start(on_update: impl Fn(Path) + 'static) -> Self {
        // SAFETY: plain object creation; both are released in Drop.
        let (monitor, queue) = unsafe {
            let queue = dispatch_queue_create(c"sbr.path-monitor".as_ptr(), std::ptr::null_mut());
            let monitor = nw_path_monitor_create();
            nw_path_monitor_set_queue(monitor, queue);
            (monitor, queue)
        };
        let handler = RcBlock::new(move |path: Object| {
            let interfaces = Rc::new(RefCell::new(Vec::new()));
            let found = interfaces.clone();
            let collect = RcBlock::new(move |interface: Object| {
                // SAFETY: the interface is valid during the enumeration.
                unsafe {
                    if nw_interface_get_type(interface) != NW_INTERFACE_TYPE_OTHER {
                        let name = nw_interface_get_name(interface);
                        if !name.is_null() {
                            found
                                .borrow_mut()
                                .push(CStr::from_ptr(name).to_string_lossy().into_owned());
                        }
                    }
                }
                // C `bool` true: keep enumerating. block2 takes no `bool`.
                1
            });
            // SAFETY: the path is valid for the duration of the handler.
            let satisfied = unsafe {
                nw_path_enumerate_interfaces(path, &collect);
                nw_path_get_status(path) == NW_PATH_STATUS_SATISFIED
            };
            drop(collect);
            on_update(Path {
                satisfied,
                interfaces: interfaces.take(),
            });
        });
        // SAFETY: the monitor copies the block.
        unsafe {
            nw_path_monitor_set_update_handler(monitor, &handler);
            nw_path_monitor_start(monitor);
        }
        PathMonitor { monitor, queue }
    }
}

impl Drop for PathMonitor {
    fn drop(&mut self) {
        // SAFETY: created in `start`, released once.
        unsafe {
            nw_path_monitor_cancel(self.monitor);
            nw_release(self.monitor);
            dispatch_release(self.queue);
        }
    }
}

/// Calls back when the system warns that memory is low, until dropped.
pub struct MemoryPressure(Object);

// SAFETY: dispatch objects may be used and released from any thread.
unsafe impl Send for MemoryPressure {}

type PressureHandler = Box<dyn Fn(bool) + Send + Sync>;

impl MemoryPressure {
    /// `on_pressure(critical)`.
    pub fn watch(on_pressure: impl Fn(bool) + Send + Sync + 'static) -> Self {
        unsafe extern "C" fn fire(context: *mut c_void) {
            let (source, handler) = unsafe { &*context.cast::<(usize, PressureHandler)>() };
            let data = unsafe { dispatch_source_get_data(*source as Object) };
            handler(data & DISPATCH_MEMORYPRESSURE_CRITICAL != 0);
        }
        unsafe extern "C" fn free(context: *mut c_void) {
            drop(unsafe { Box::from_raw(context.cast::<(usize, PressureHandler)>()) });
        }
        // SAFETY: a memory pressure source on a global queue; the context is
        // freed by the finalizer when the source is released.
        unsafe {
            let queue = dispatch_get_global_queue(0, 0);
            let source = dispatch_source_create(
                &raw const _dispatch_source_type_memorypressure,
                0,
                DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL,
                queue,
            );
            let handler: PressureHandler = Box::new(on_pressure);
            let context = Box::into_raw(Box::new((source as usize, handler)));
            dispatch_set_context(source, context.cast());
            dispatch_set_finalizer_f(source, free);
            dispatch_source_set_event_handler_f(source, fire);
            dispatch_resume(source);
            MemoryPressure(source)
        }
    }
}

impl Drop for MemoryPressure {
    fn drop(&mut self) {
        // SAFETY: created in `watch`, released once.
        unsafe {
            dispatch_source_cancel(self.0);
            dispatch_release(self.0);
        }
    }
}
