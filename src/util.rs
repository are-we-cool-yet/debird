//! A grab-bag of cursed macros and utilities.

use std::collections::HashMap;

use winapi::um::winnt::PIMAGE_THUNK_DATA;


#[derive(Clone)]
pub struct Imports<'a> {
    import_map: HashMap<&'a str, PIMAGE_THUNK_DATA>,
}

impl<'a> Imports<'a> {
    pub fn new(import_map: HashMap<&'a str, PIMAGE_THUNK_DATA>) -> Self {
        Self { import_map }
    }

    pub fn get(&self, name: &str) -> Option<PIMAGE_THUNK_DATA> {
        self.import_map.get(name).copied()
    }

    pub fn import_map(&self) -> &HashMap<&'a str, PIMAGE_THUNK_DATA> {
        &self.import_map
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
pub const unsafe fn offset_addr<T>(ptr: usize, offset: isize) -> *mut T {
    unsafe { (ptr as *mut T).byte_offset(offset) }
}

/// A macro that creates hooks.
#[macro_export]
macro_rules! create_hooks {
    { $hooks:ident: $( $i:ident; )+ } => {
        $( $crate::hook::Hooks::hook(&mut $hooks, stringify!($i), $crate::hook::$i as *mut ::core::ffi::c_void)? );+
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
