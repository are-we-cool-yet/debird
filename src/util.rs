//! A grab-bag of cursed macros and utilities.

use std::collections::HashMap;

use pelite::pe64::{Pe, PeFile, Va, imports::Import};

use crate::error;

pub struct Imports<'a> {
    import_map: HashMap<&'a str, (String, Va)>,
    image_base: usize,
}

impl<'a> Imports<'a> {
    pub fn from_pe_file(pe_file: &'a PeFile<'a>) -> error::Result<Self> {
        let imports = pe_file.imports()?.into_iter();
        let mut import_map = HashMap::with_capacity(imports.len());
        for import_dll in imports {
            let dll_name = import_dll.dll_name()?.to_string();
            for (&import_va, import_name) in Iterator::zip(import_dll.iat()?, import_dll.int()?) {
                if let Import::ByName { hint: _hint, name } = import_name? {
                    import_map.insert(name.to_str()?, (dll_name.clone(), import_va));
                }
            }
        }

        Ok(Self {
            import_map,
            image_base: pe_file.optional_header().ImageBase as usize,
        })
    }

    pub fn iter(&'_ self) -> std::collections::hash_map::Iter<'_, &'a str, (String, Va)> {
        self.import_map.iter()
    }

    pub fn get(&self, name: &str) -> Option<Va> {
        self.import_map.get(name).map(|(_, b)| b).copied()
    }

    /// # Safety
    /// The caller assumes the safety responsibilities of [`offset_addr`].
    pub unsafe fn find_fn<T>(&self, name: &str, offset: isize) -> error::Result<*mut T> {
        if let Some(ptr) = self.get(name) {
            Ok(offset_addr(ptr as usize, self.image_base, offset))
        } else {
            Err(error::Error::HookImportNotFound(error::ImportNotFound(name.to_string())))
        }
    }
}

pub const fn from_base(addr: usize, base: usize) -> usize {
    addr - base
}

/// # Safety
/// The caller assumes the responsibilities that offsetting the
/// given pointer by the given offset is not used to break aliasing
/// rules or other borrowing rules and that the resulting address is valid
/// and can be cast to the specified type.
pub const unsafe fn offset_addr<T>(ptr: usize, base: usize, offset: isize) -> *mut T {
    (from_base(ptr, base) as *mut T).byte_offset(offset)
}

/// A macro that creates hooks.
#[macro_export]
macro_rules! create_hooks {
    { ($handle:ident, $imports:ident): $( $i:ident; )+ } => {
        $( minhook::MinHook::create_hook(*$crate::util::Imports::find_fn(&$imports, stringify!($i), $handle)?, $crate::hook::$i as _)? );+
    };
}

/// A macro that converts C #define preprocessors into constants.
#[macro_export]
macro_rules! c_define {
    ( $vis:vis $ty:ty: $( #define $i:ident $value:literal )+ ) => {
        $( $vis const $i: $ty = $value; )+
    };
    ( #[$attr:meta] $vis:vis $ty:ty: $( #define $i:ident $value:literal )+ ) => {
        $( #[$attr] $vis const $i: $ty = $value; )+
    };
}

/// A tiny DSL for easily casting to raw pointers.
#[macro_export]
macro_rules! ptr {
    ( *const $expr:expr ) => {
        &$expr as *const _
    };
    ( *mut $expr:expr ) => {
        &mut $expr as *mut _
    };
}

/// A tiny DSL for easily instantiating ManuallyDrops.
#[macro_export]
macro_rules! manually_drop {
    ( *const null ) => {
        $crate::manually_drop!(core::ptr::null())
    };
    ( *mut null ) => {
        $crate::manually_drop!(core::ptr::null_mut())
    };
    ( *const $expr:expr ) => {
        $crate::manually_drop!($crate::ptr!(*const $expr))
    };
    ( *mut $expr:expr ) => {
        $crate::manually_drop!($crate::ptr!(*mut $expr))
    };
    ( $value:expr ) => {
        core::mem::ManuallyDrop::new($value)
    };
}
