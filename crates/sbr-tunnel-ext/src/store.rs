//! Where the tunnel keeps things: its private directory, the App Group
//! container, and the Keychain items it shares with the app.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{
    NSData, NSFileManager, NSMutableDictionary, NSNumber, NSSearchPathDirectory, NSSearchPathDomainMask, NSString,
    NSURL,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The extension's own directory: where relative paths in the config
/// (cache_file, local rule-sets) live when no App Group is configured, and
/// where the tunnel keeps its session files. Application Support, except on
/// tvOS, which has no persistent files and so uses the caches directory (the
/// system may purge it; everything there is rebuilt). The cache and logs name
/// servers and destinations: the directory is kept out of backups, and files
/// created in it inherit its protection (readable after first unlock, for
/// on-demand starts).
pub fn private_dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let kind = if cfg!(target_os = "tvos") {
            NSSearchPathDirectory::CachesDirectory
        } else {
            NSSearchPathDirectory::ApplicationSupportDirectory
        };
        let fm = NSFileManager::defaultManager();
        let base = fm
            .URLsForDirectory_inDomains(kind, NSSearchPathDomainMask::UserDomainMask)
            .firstObject()?;
        let dir = PathBuf::from(base.path()?.to_string()).join("sbr");
        let _ = std::fs::create_dir_all(&dir);
        let path = NSString::from_str(&dir.to_string_lossy());
        #[cfg(not(target_os = "macos"))]
        // SAFETY: the keys and values are the documented NSFileManager ones.
        unsafe {
            use objc2_foundation::{
                NSFileProtectionCompleteUntilFirstUserAuthentication, NSFileProtectionKey,
            };
            let attrs = NSMutableDictionary::<NSString, AnyObject>::new();
            attrs.insert(NSFileProtectionKey, NSFileProtectionCompleteUntilFirstUserAuthentication.as_ref());
            let _: bool = msg_send![&fm, setAttributes: &*attrs, ofItemAtPath: &*path, error: std::ptr::null_mut::<*mut AnyObject>()];
        }
        let url = NSURL::fileURLWithPath(&path);
        // SAFETY: NSURLIsExcludedFromBackupKey takes an NSNumber boolean.
        unsafe {
            let yes = NSNumber::new_bool(true);
            let _: bool = msg_send![&url, setResourceValue: &*yes, forKey: objc2_foundation::NSURLIsExcludedFromBackupKey, error: std::ptr::null_mut::<*mut AnyObject>()];
        }
        Some(dir)
    })
    .as_deref()
}

pub fn private_file(name: &str) -> Option<PathBuf> {
    private_dir().map(|d| d.join(name))
}

/// The App Group container: also the base directory for relative paths in
/// the config.
pub fn app_group_dir(group: &str) -> Option<PathBuf> {
    let url = NSFileManager::defaultManager()
        .containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(group))?;
    Some(PathBuf::from(url.path()?.to_string()))
}

/// `config.json` in the App Group container.
pub fn load_app_group_config(group: &str) -> Result<String, String> {
    let dir =
        app_group_dir(group).ok_or_else(|| format!("App Group {group} is not available (entitlement missing?)"))?;
    let path = dir.join("config.json");
    std::fs::read_to_string(&path).map_err(|e| format!("no config at {}: {e}", path.display()))
}

/// Write `data` to `path` atomically. The file inherits the directory's
/// protection and backup exclusion.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

// The Security framework's SecItem API. The CFString constants are
// toll-free bridged NSStrings, and CFBoolean is an NSNumber.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecClass: &'static NSString;
    static kSecClassGenericPassword: &'static NSString;
    static kSecAttrService: &'static NSString;
    static kSecAttrAccount: &'static NSString;
    static kSecAttrAccessGroup: &'static NSString;
    static kSecAttrSynchronizable: &'static NSString;
    static kSecAttrAccessible: &'static NSString;
    static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: &'static NSString;
    static kSecUseDataProtectionKeychain: &'static NSString;
    static kSecReturnData: &'static NSString;
    static kSecMatchLimit: &'static NSString;
    static kSecMatchLimitOne: &'static NSString;
    static kSecValueData: &'static NSString;

    fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemUpdate(query: *const c_void, attributes: *const c_void) -> i32;
    fn SecCopyErrorMessageString(status: i32, reserved: *const c_void) -> *const c_void;
}

const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Generic-password items in one Keychain access group, as SbrKit's
/// `SbrKeychain` stores them: service `sbr`, never synchronised, readable
/// after first unlock, in the data protection Keychain.
pub struct Keychain<'a> {
    pub access_group: &'a str,
}

impl Keychain<'_> {
    const SERVICE: &'static str = "sbr";

    fn base(&self, account: &str) -> Retained<NSMutableDictionary<NSString, AnyObject>> {
        let q = NSMutableDictionary::<NSString, AnyObject>::new();
        // SAFETY: the Security constants are valid for the process lifetime.
        unsafe {
            q.insert(kSecClass, kSecClassGenericPassword.as_ref());
            q.insert(kSecAttrService, NSString::from_str(Self::SERVICE).as_ref());
            q.insert(kSecAttrSynchronizable, NSNumber::new_bool(false).as_ref());
            q.insert(kSecAttrAccount, NSString::from_str(account).as_ref());
            q.insert(kSecAttrAccessGroup, NSString::from_str(self.access_group).as_ref());
            q.insert(kSecUseDataProtectionKeychain, NSNumber::new_bool(true).as_ref());
        }
        q
    }

    pub fn data(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
        let q = self.base(account);
        // SAFETY: as in `base`.
        unsafe {
            q.insert(kSecReturnData, NSNumber::new_bool(true).as_ref());
            q.insert(kSecMatchLimit, kSecMatchLimitOne.as_ref());
        }
        let mut result: *const c_void = std::ptr::null();
        // SAFETY: a valid dictionary; on success `result` is a +1 CFData.
        let status = unsafe { SecItemCopyMatching(Retained::as_ptr(&q).cast(), &mut result) };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        check(status, "read")?;
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: the Copy rule hands us ownership of an NSData.
        let data = unsafe { Retained::from_raw(result.cast_mut().cast::<NSData>()) };
        Ok(data.map(|d| d.to_vec()))
    }

    pub fn set(&self, account: &str, data: &[u8]) -> Result<(), String> {
        let attrs = NSMutableDictionary::<NSString, AnyObject>::new();
        // SAFETY: as in `base`.
        unsafe {
            attrs.insert(kSecValueData, NSData::with_bytes(data).as_ref());
            attrs.insert(
                kSecAttrAccessible,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.as_ref(),
            );
        }
        let q = self.base(account);
        // SAFETY: valid dictionaries.
        let status = unsafe { SecItemUpdate(Retained::as_ptr(&q).cast(), Retained::as_ptr(&attrs).cast()) };
        if status != ERR_SEC_ITEM_NOT_FOUND {
            return check(status, "update");
        }
        // SAFETY: as in `base`.
        unsafe {
            q.insert(kSecValueData, NSData::with_bytes(data).as_ref());
            q.insert(
                kSecAttrAccessible,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.as_ref(),
            );
        }
        // SAFETY: a valid dictionary; no result requested.
        check(
            unsafe { SecItemAdd(Retained::as_ptr(&q).cast(), std::ptr::null_mut()) },
            "add",
        )
    }

    pub fn value<T: DeserializeOwned>(&self, account: &str) -> Result<Option<T>, String> {
        self.data(account)?
            .map(|d| serde_json::from_slice(&d).map_err(|e| e.to_string()))
            .transpose()
    }

    pub fn set_value(&self, account: &str, value: &impl Serialize) -> Result<(), String> {
        self.set(account, &serde_json::to_vec(value).map_err(|e| e.to_string())?)
    }
}

fn check(status: i32, op: &str) -> Result<(), String> {
    if status == ERR_SEC_SUCCESS {
        return Ok(());
    }
    // SAFETY: returns a +1 CFString (an NSString) or NULL.
    let message = unsafe {
        Retained::from_raw(
            SecCopyErrorMessageString(status, std::ptr::null())
                .cast_mut()
                .cast::<NSString>(),
        )
    }
    .map_or_else(|| format!("OSStatus {status}"), |s| s.to_string());
    Err(format!("keychain {op} failed: {message}"))
}
