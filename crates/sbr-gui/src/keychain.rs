//! Generic-password items in one Keychain access group, shared by the app
//! and its tunnel extension: SbrKit's `SbrKeychain`. Items are readable after
//! the first unlock (so an on-demand tunnel can start), never synchronised,
//! and never leave the device: a backup restored onto another device does
//! not bring them. On macOS they live in the data protection Keychain, which
//! honours access groups and accessibility.
//!
//! Query dictionaries are built as `NSDictionary`, which is toll-free
//! bridged to the `CFDictionary` the Security functions take.

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_core_foundation::{CFDictionary, CFString, CFType};
use objc2_foundation::{NSArray, NSData, NSDictionary, NSMutableDictionary, NSNumber, NSString};
use objc2_security::{
    SecCopyErrorMessageString, SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate, errSecItemNotFound,
    errSecSuccess, kSecAttrAccessGroup, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
    kSecMatchLimitAll, kSecMatchLimitOne, kSecReturnAttributes, kSecReturnData, kSecUseDataProtectionKeychain,
    kSecValueData,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Clone, Debug)]
pub struct Keychain {
    /// `<team prefix>.<identifier>`, as in the `keychain-access-groups`
    /// entitlement. None uses the process's default group.
    pub access_group: Option<String>,
    pub service: String,
}

/// A `CFString` constant as the `NSString` it is bridged to.
fn ns(s: &CFString) -> &NSString {
    // SAFETY: CFString and NSString are toll-free bridged.
    unsafe { &*(s as *const CFString).cast::<NSString>() }
}

/// A `CFType` constant as the Objective-C object it is bridged to.
fn obj(s: &CFString) -> &AnyObject {
    // SAFETY: every CFType is an Objective-C object.
    unsafe { &*(s as *const CFString).cast::<AnyObject>() }
}

fn cf(d: &NSDictionary<NSString, AnyObject>) -> &CFDictionary {
    // SAFETY: NSDictionary and CFDictionary are toll-free bridged.
    unsafe { &*(d as *const NSDictionary<NSString, AnyObject>).cast::<CFDictionary>() }
}

/// The access group the app shares with its tunnel, from Info.plist
/// (`SbrKeychainGroup`), or `SBR_KEYCHAIN_GROUP` for an unbundled run.
pub fn app_group() -> Option<String> {
    if let Ok(g) = std::env::var("SBR_KEYCHAIN_GROUP") {
        return Some(g).filter(|g| !g.is_empty());
    }
    let key = NSString::from_str("SbrKeychainGroup");
    let value = objc2_foundation::NSBundle::mainBundle().objectForInfoDictionaryKey(&key)?;
    let value = value.downcast::<NSString>().ok()?;
    Some(value.to_string()).filter(|s| !s.is_empty())
}

impl Keychain {
    pub fn new(access_group: Option<String>) -> Self {
        Keychain {
            access_group,
            service: "sbr".into(),
        }
    }

    pub fn data(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
        let q = self.base(Some(account));
        unsafe {
            q.insert(ns(kSecReturnData), &*NSNumber::new_bool(true));
            q.insert(ns(kSecMatchLimit), obj(kSecMatchLimitOne));
        }
        let mut result: *const CFType = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(cf(&q), &mut result) };
        if status == errSecItemNotFound {
            return Ok(None);
        }
        check(status, "read")?;
        // SAFETY: a +1 reference to the item's data, as kSecReturnData asks.
        let data = unsafe { Retained::from_raw(result.cast_mut().cast::<NSData>()) };
        Ok(data.map(|d| d.to_vec()))
    }

    pub fn set(&self, data: &[u8], account: &str) -> Result<(), String> {
        let attributes = NSMutableDictionary::<NSString, AnyObject>::new();
        let value = NSData::with_bytes(data);
        unsafe {
            attributes.insert(ns(kSecValueData), &*value);
            attributes.insert(
                ns(kSecAttrAccessible),
                obj(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            );
        }
        let query = self.base(Some(account));
        let status = unsafe { SecItemUpdate(cf(&query), cf(&attributes)) };
        if status != errSecItemNotFound {
            return check(status, "update");
        }
        let (keys, values) = attributes.to_vecs();
        for (k, v) in keys.iter().zip(values.iter()) {
            query.insert(&**k, &**v);
        }
        check(unsafe { SecItemAdd(cf(&query), std::ptr::null_mut()) }, "add")
    }

    pub fn remove(&self, account: &str) -> Result<(), String> {
        let status = unsafe { SecItemDelete(cf(&self.base(Some(account)))) };
        if status == errSecItemNotFound {
            return Ok(());
        }
        check(status, "delete")
    }

    /// Every account in this service and group.
    pub fn accounts(&self) -> Result<Vec<String>, String> {
        let q = self.base(None);
        unsafe {
            q.insert(ns(kSecReturnAttributes), &*NSNumber::new_bool(true));
            q.insert(ns(kSecMatchLimit), obj(kSecMatchLimitAll));
        }
        let mut result: *const CFType = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(cf(&q), &mut result) };
        if status == errSecItemNotFound {
            return Ok(Vec::new());
        }
        check(status, "list")?;
        // SAFETY: a +1 array of attribute dictionaries.
        let items =
            unsafe { Retained::from_raw(result.cast_mut().cast::<NSArray<NSDictionary<NSString, AnyObject>>>()) };
        let key = unsafe { ns(kSecAttrAccount) };
        Ok(items
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.objectForKey(key)?.downcast::<NSString>().ok())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Delete every item in this service and group.
    pub fn remove_all(&self) -> Result<(), String> {
        let status = unsafe { SecItemDelete(cf(&self.base(None))) };
        if status == errSecItemNotFound {
            return Ok(());
        }
        check(status, "delete")
    }

    /// A JSON item, decoded. An item that does not decode is an error.
    pub fn value<T: DeserializeOwned>(&self, account: &str) -> Result<Option<T>, String> {
        self.data(account)?
            .map(|d| serde_json::from_slice(&d).map_err(|e| format!("keychain item {account}: {e}")))
            .transpose()
    }

    pub fn set_value(&self, value: &impl Serialize, account: &str) -> Result<(), String> {
        self.set(&serde_json::to_vec(value).map_err(|e| e.to_string())?, account)
    }

    fn base(&self, account: Option<&str>) -> Retained<NSMutableDictionary<NSString, AnyObject>> {
        let q = NSMutableDictionary::<NSString, AnyObject>::new();
        unsafe {
            q.insert(ns(kSecClass), obj(kSecClassGenericPassword));
            q.insert(ns(kSecAttrService), &*NSString::from_str(&self.service));
            q.insert(ns(kSecAttrSynchronizable), &*NSNumber::new_bool(false));
            if let Some(account) = account {
                q.insert(ns(kSecAttrAccount), &*NSString::from_str(account));
            }
            if let Some(group) = &self.access_group {
                q.insert(ns(kSecAttrAccessGroup), &*NSString::from_str(group));
            }
            q.insert(ns(kSecUseDataProtectionKeychain), &*NSNumber::new_bool(true));
        }
        q
    }
}

fn check(status: i32, op: &str) -> Result<(), String> {
    if status == errSecSuccess {
        return Ok(());
    }
    let message = unsafe { SecCopyErrorMessageString(status, std::ptr::null_mut()) }
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("OSStatus {status}"));
    Err(format!("keychain {op} failed: {message}"))
}
