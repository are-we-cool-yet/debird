//! A collection of hooks and patches.
#![allow(non_snake_case)]

use std::{cell::RefCell, collections::VecDeque};

use winapi::{shared::{minwindef, ntdef}, um::{errhandlingapi::GetLastError, memoryapi::VirtualProtectEx, processthreadsapi::GetCurrentProcess, winnt::PAGE_READWRITE}};

use crate::{constants, ptr, types::{KPROCESSOR_MODE, LOCK_OPERATION, MDL, MEMORY_CACHING_TYPE, QWORD}, DECRYPT_TX};

thread_local! {
    static MDL_LIST: RefCell<VecDeque<MDL>> = RefCell::new(VecDeque::new());
    pub static DATA_ID: RefCell<usize> = RefCell::new(usize::MAX);
    pub static CHUNK_ID: RefCell<usize> = RefCell::new(usize::MAX);
}

/// Replace the first six bytes of the main entrypoint with these bytes.
/// Do note that there are multiple entrypoints; you want the one that is called upon driver initialization (the "true" entrypoint).
/// ```asm
/// mov eax, 1
/// ret
/// ```
pub const CANCEL_DRIVER_ENTRY: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
pub const TRUE_DRIVER_ENTRY: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3];

pub unsafe extern "fastcall" fn MmChangeImageProtection(_arg0: QWORD, _arg1: QWORD, _arg2: QWORD, _arg3: QWORD) -> winapi::ctypes::__int64 {
    println!("MmChangeImageProtection");
    minwindef::TRUE as _
}

pub unsafe extern "stdcall" fn IoAllocateMdl(virtual_address: ntdef::PVOID, length: ntdef::ULONG, _secondary_buffer: ntdef::BOOLEAN, _charge_quota: ntdef::BOOLEAN, irp: ntdef::PVOID) -> *mut MDL {
    print!("IoAllocateMdl (VA @ 0x{:X})    ", virtual_address as usize);
    if !irp.is_null() {
        panic!("Non-null IRP found! Non-null IRPs are unsupported.");
    }

    // Mark the specified Virtual Address as Read-Write.
    let process_handle = GetCurrentProcess();
    let mut old_protect = 0;
    let mapped_virtual_address = VirtualProtectEx(process_handle, virtual_address, length as usize, PAGE_READWRITE, &mut old_protect);
    if mapped_virtual_address == minwindef::FALSE {
        let error = GetLastError();
        panic!("Failed to allocate memory @ 0x{:X}\nError Code: 0x{error:X}\nProcess Handle: 0x{:X}", virtual_address as usize, process_handle as isize);
    }

    // Initialize Memory Descriptor List
    let mdl = MDL {
        next: core::ptr::null_mut(),
        size: length as _,
        mdl_flags: constants::MDL_MAPPED_TO_SYSTEM_VA,
        process: ptr!(*const constants::EPROCESS),
        mapped_system_va: virtual_address,
        start_va: virtual_address,
        byte_count: length,
        byte_offset: 0,
    };

    MDL_LIST.with_borrow_mut(|list| list.push_back(mdl));
    let mdl_ptr = MDL_LIST.with_borrow_mut(|list| list.back_mut().unwrap() as *mut _);
    println!("Allocated MDL (MDL @ 0x{:X})", mdl_ptr as *const _ as usize);
    mdl_ptr as *mut MDL
}

pub unsafe extern "stdcall" fn IoFreeMdl(mdl: *mut MDL) {
    println!("IoFreeMdl (MDL @ 0x{:X})", mdl as usize);
    assert!(!mdl.is_null());

    // Gather and send decrypted page to the main thread
    let len = (*mdl).byte_count as usize;
    let mut data = vec![0; len];
    data.extend_from_slice(core::ptr::slice_from_raw_parts((*mdl).start_va as *const u8, len).as_ref().expect("decrypted data should not be null"));
    let data_id = DATA_ID.with_borrow(|x| x.clone());
    let chunk_id = CHUNK_ID.with_borrow(|x| x.clone());
    CHUNK_ID.replace(chunk_id + 1);
    println!("{data_id}@{chunk_id}");
    DECRYPT_TX.send((data, data_id, chunk_id)).unwrap();

    MDL_LIST.with_borrow_mut(|list| list.remove(list.iter().position(|x| x as *const _ == mdl).unwrap()));
}

pub unsafe extern "stdcall" fn MmProbeAndLockPages(memory_descriptor_list: *mut MDL, _access_mode: KPROCESSOR_MODE, _operation: LOCK_OPERATION) {
    println!("MmProbeAndLockPages (MDL @ {:X})", memory_descriptor_list as usize);
}

pub unsafe extern "stdcall" fn MmUnlockPages(memory_descriptor_list: *mut MDL) {
    print!("MmUnlockPages (MDL @ 0x{:X})    ", memory_descriptor_list as usize);
    print!("MDL Flags Before 0x{:X}    ", (*memory_descriptor_list).mdl_flags);
    (*memory_descriptor_list).mdl_flags = 0;
    println!("MDL Flags After 0x{:X}", (*memory_descriptor_list).mdl_flags);
}

pub unsafe extern "stdcall" fn MmLockPagableDataSection(address_within_section: ntdef::PVOID) -> ntdef::PVOID {
    println!("MmLockPagableDataSection (0x{:X})", address_within_section as usize);
    address_within_section
}

pub unsafe extern "stdcall" fn MmMapLockedPagesSpecifyCache(_memory_descriptor_list: *mut MDL, _access_mode: KPROCESSOR_MODE, _cache_type: MEMORY_CACHING_TYPE) -> ntdef::PVOID {
    println!("MmMapLockedPagesSpecifyCache");
    0x0 as _
}

pub unsafe extern "stdcall" fn MmUnmapLockedPages(_base_address: ntdef::PVOID, _memory_descriptor_list: *mut MDL) {
    println!("MmUnmapLockedPages");
}
