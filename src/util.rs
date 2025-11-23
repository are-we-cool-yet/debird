//! A grab-bag of cursed macros and utilities.

use crate::constants;

const fn from_base(addr: usize) -> usize {
    addr - constants::DLL_BASE
}

/// # Safety
/// The caller assumes the responsibility that offsetting the
/// given pointer by the given offset is not used to break aliasing
/// rules or other borrowing rules and that the resulting address is valid
/// and can be cast to the specified type.
pub const unsafe fn offset_addr<T>(ptr: usize, offset: isize) -> *mut T {
    (from_base(ptr) as *mut T).byte_offset(offset)
}

/// A less cursed-ass macro that creates hooks.
#[macro_export]
macro_rules! create_hooks_with_handle {
    { $handle:ident: $( $i:ident; )+ } => {
        $( minhook::MinHook::create_hook(*$crate::constants::$i($handle), $crate::hook::$i as _)? );+
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
