//! A strict JSON object reader.
//!
//! sing-box rejects unknown fields. We go one further and tell the user
//! *which* path was rejected and whether sbr simply hasn't implemented it yet.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::{Error, Result};

pub(crate) struct Diag {
    pub warnings: Vec<String>,
}

pub(crate) struct Obj {
    map: Map<String, Value>,
    path: String,
}

impl Obj {
    pub fn new(value: Value, path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        match value {
            Value::Object(map) => Ok(Self { map, path }),
            other => Err(Error::at(&path, format!("expected object, got {}", kind(&other)))),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn sub(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{key}", self.path)
        }
    }

    /// Remaining keys, for map-shaped objects.
    pub fn keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    pub fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    pub fn raw(&mut self, key: &str) -> Option<Value> {
        self.map.remove(key).filter(|v| !v.is_null())
    }

    pub fn opt<T: DeserializeOwned>(&mut self, key: &str) -> Result<Option<T>> {
        match self.raw(key) {
            None => Ok(None),
            Some(v) => serde_json::from_value(v)
                .map(Some)
                .map_err(|e| Error::at(&self.sub(key), e.to_string())),
        }
    }

    pub fn get<T: DeserializeOwned + Default>(&mut self, key: &str) -> Result<T> {
        Ok(self.opt(key)?.unwrap_or_default())
    }

    pub fn req<T: DeserializeOwned>(&mut self, key: &str) -> Result<T> {
        self.opt(key)?
            .ok_or_else(|| Error::at(&self.sub(key), "missing required field"))
    }

    /// sing-box `Listable`: accepts a single value or an array.
    pub fn list<T: DeserializeOwned>(&mut self, key: &str) -> Result<Vec<T>> {
        match self.raw(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    serde_json::from_value(v).map_err(|e| Error::at(&format!("{}[{i}]", self.sub(key)), e.to_string()))
                })
                .collect(),
            Some(v) => serde_json::from_value(v)
                .map(|x| vec![x])
                .map_err(|e| Error::at(&self.sub(key), e.to_string())),
        }
    }

    pub fn bool(&mut self, key: &str) -> Result<bool> {
        self.get(key)
    }

    pub fn string(&mut self, key: &str) -> Result<Option<String>> {
        Ok(self.opt::<String>(key)?.filter(|s| !s.is_empty()))
    }

    pub fn duration(&mut self, key: &str) -> Result<Option<std::time::Duration>> {
        let path = self.sub(key);
        match self.raw(key) {
            None => Ok(None),
            Some(Value::String(s)) if s.is_empty() => Ok(None),
            Some(Value::String(s)) => crate::types::parse_duration(&s)
                .map(Some)
                .map_err(|e| Error::at(&path, e)),
            // sing-box accepts bare integers as nanoseconds-free seconds in a few legacy spots; be explicit instead.
            Some(other) => Err(Error::at(
                &path,
                format!("expected duration string like \"5s\", got {}", kind(&other)),
            )),
        }
    }

    /// Fields that sing-box accepts that we deliberately ignore (performance
    /// hints, platform-specific knobs). Present-and-truthy produces a warning.
    pub fn tolerate(&mut self, diag: &mut Diag, keys: &[&str]) {
        for key in keys {
            if let Some(v) = self.raw(key)
                && truthy(&v)
            {
                diag.warnings.push(format!("{}: ignored by sbr", self.sub(key)));
            }
        }
    }

    pub fn finish(self) -> Result<()> {
        if let Some(key) = self.map.keys().next() {
            let path = if self.path.is_empty() {
                key.clone()
            } else {
                format!("{}.{key}", self.path)
            };
            return Err(Error::at(&path, "unknown field, or not supported by sbr yet"));
        }
        Ok(())
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
    }
}

pub(crate) fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
