//! A collection of hooks and patches.
#![allow(non_snake_case)]

use std::{cell::RefCell, collections::{HashMap, VecDeque}, ffi::{CStr, c_void}};

use fn_abi::abi;
use winapi::{shared::{minwindef::{self, HMODULE, LPVOID}, ntdef}, um::{errhandlingapi::GetLastError, memoryapi::{VirtualProtect, VirtualProtectEx}, processthreadsapi::GetCurrentProcess, winnt::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG, PAGE_READWRITE, PIMAGE_DOS_HEADER, PIMAGE_IMPORT_BY_NAME, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS, PIMAGE_THUNK_DATA}}};

use crate::{DECRYPT_TX, constants, error, hook, ptr, types::{KPROCESSOR_MODE, LOCK_OPERATION, MDL, MEMORY_CACHING_TYPE, QWORD}, util::Imports};

thread_local! {
    static MDL_LIST: RefCell<VecDeque<MDL>> = const { RefCell::new(VecDeque::new()) };
    pub static DATA_ID: RefCell<usize> = const { RefCell::new(usize::MAX) };
    pub static CHUNK_ID: RefCell<usize> = const { RefCell::new(usize::MAX) };
}

pub struct Hooks<'a> {
    image_base: *mut c_void,
    imports: Imports<'a>,
    hooked: HashMap<&'a str, (*mut c_void, *mut c_void)>,
}

impl<'a> Hooks<'a> {
    /// # Safety
    /// The caller guarantees that `process_handle` is a [`HMODULE`] pointing to an existing
    /// Win32 process or library accessible to the current process and lives at least as long
    /// as this type lives.
    pub unsafe fn new(process_handle: HMODULE) -> error::Result<Self> {
        unsafe {
            // https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
            // ^ References
            let image_base = process_handle as *mut c_void;
            let dos_headers = image_base as PIMAGE_DOS_HEADER;
            let nt_headers = image_base.byte_add((*dos_headers).e_lfanew as usize) as PIMAGE_NT_HEADERS;
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
            let import_directory = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

            let mut import_map = HashMap::new();
            // import directory entry
            let mut import_descriptor = image_base
                .byte_add(import_directory.VirtualAddress as usize) as PIMAGE_IMPORT_DESCRIPTOR;
            while (*import_descriptor).Name != 0 {
                let dll_name = CStr::from_ptr(image_base.byte_add((*import_descriptor).Name as usize) as *mut i8);
                println!("Found {} in import descriptor entry", dll_name.to_string_lossy());

                let mut original_first_thunk = image_base.byte_add(*(*import_descriptor).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA;
                let mut first_thunk = image_base.byte_add((*import_descriptor).FirstThunk as usize) as PIMAGE_THUNK_DATA;
                while *(*original_first_thunk).u1.AddressOfData() != 0 {
                    if *(*original_first_thunk).u1.Ordinal() & IMAGE_ORDINAL_FLAG == 0 {
                        let import_by_name = image_base.byte_add(*(*original_first_thunk).u1.AddressOfData() as usize) as PIMAGE_IMPORT_BY_NAME;
                        let function_name = CStr::from_ptr((*import_by_name).Name.as_ptr()).to_str()?;
                        import_map.insert(function_name, first_thunk as PIMAGE_THUNK_DATA);
                    }

                    original_first_thunk = original_first_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }

                import_descriptor = import_descriptor.add(1);
            }

            let imports = Imports::new(import_map);

            Ok(Self {
                image_base,
                imports,
                hooked: HashMap::new(),
            })
        }
    }

    /// # Safety
    /// The caller is responsible for providing an accurate detour function.
    /// The safety requirements of [`Hooks::new`] apply also.
    pub unsafe fn hook(&mut self, function_name: &'a str, function_detour: *mut c_void) -> error::Result<()> {
        let iat = self.imports.get(function_name)
            .ok_or(error::Error::HookImportNotFound(error::ImportNotFound(function_name.to_string())))? as PIMAGE_THUNK_DATA;

        unsafe {
            let import_function = (*iat).u1.Function_mut() as *mut u64;

            // Don't forget to set it as writable!
            let mut old_protect = 0u32;
            let status = VirtualProtect(import_function as LPVOID, size_of::<u64>(), PAGE_READWRITE, &mut old_protect as *mut u32);
            if status == 0 {
                panic!("Error while using VirtualProtect during hooking: {:#X}", GetLastError());
            }

            let original_function = *import_function;
            *import_function = function_detour.byte_sub(self.image_base as usize) as u64;
            self.hooked.insert(function_name, (original_function as *mut c_void, function_detour));

            // Don't forget to also *unset* it.
            let status = VirtualProtect(import_function as LPVOID, size_of::<u64>(), old_protect, &mut old_protect as *mut u32);
            if status == 0 {
                panic!("Error while using VirtualProtect during hooking: {:#X}", GetLastError());
            }
        }

        Ok(())
    }

    /// Hook unhooked functions to a dummy function.
    /// This is useful when you need to hijack the exports/imports
    /// but don't care about the other functions and would rather
    /// them be no-op.
    ///
    /// # Safety
    /// The caller assumes the same responsibilities as [`Hooks::hook`].
    pub unsafe fn hook_unused_as_dummies(&mut self) -> error::Result<()> {
        let mut hooks = Vec::new();

        // add existing imports to a Vec for later
        let imports = RefCell::new(self.imports.import_map().clone());
        let imports_borrow = imports.borrow();
        for (function_name, _) in imports_borrow.iter() {
            hooks.push(*function_name);
        }

        drop(imports_borrow);

        // remove already hooked functions
        for function_name in self.hooked.keys() {
            imports.borrow_mut().remove(function_name);
        }

        for function_name in hooks {
            unsafe { self.hook(function_name, hook::dummy as *mut c_void)?; }
        }

        Ok(())
    }
}

#[abi("system")]
/// # Safety
pub unsafe extern fn dummy() {}

/// Replace the first six bytes of the main entrypoint with these bytes.
/// Do note that there are multiple entrypoints; you want the one that is called upon driver initialization (the "true" entrypoint).
/// ```asm
/// mov eax, 1
/// ret
/// ```
pub const CANCEL_DRIVER_ENTRY: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

#[abi("system")]
/// # Safety
pub unsafe extern fn MmChangeImageProtection(_arg0: QWORD, _arg1: QWORD, _arg2: QWORD, _arg3: QWORD) -> winapi::ctypes::__int64 {
    println!("MmChangeImageProtection");
    minwindef::TRUE as _
}

#[abi("system")]
/// # Safety
pub unsafe extern fn IoAllocateMdl(virtual_address: ntdef::PVOID, length: ntdef::ULONG, _secondary_buffer: ntdef::BOOLEAN, _charge_quota: ntdef::BOOLEAN, irp: ntdef::PVOID) -> *mut MDL {
    unsafe {
        print!("IoAllocateMdl (VA @ {:#X})    ", virtual_address as usize);
        if !irp.is_null() {
            panic!("Non-null IRP found! Non-null IRPs are unsupported.");
        }

        // Mark the specified Virtual Address as Read-Write.
        let process_handle = GetCurrentProcess();
        let mut old_protect = 0;
        let mapped_virtual_address = VirtualProtectEx(process_handle, virtual_address, length as usize, PAGE_READWRITE, &mut old_protect);
        if mapped_virtual_address == minwindef::FALSE {
            let error = GetLastError();
            panic!("Failed to allocate memory @ {:#X}\nError Code: {error:#X}\nProcess Handle: {:#X}", virtual_address as usize, process_handle as isize);
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
        println!("Allocated MDL (MDL @ {:#X})", mdl_ptr as *const _ as usize);
        mdl_ptr
    }
}

#[abi("system")]
/// # Safety
pub unsafe extern fn IoFreeMdl(mdl: *mut MDL) {
    unsafe {
        println!("IoFreeMdl (MDL @ {:#X})", mdl as usize);
        assert!(!mdl.is_null());

        // Gather and send decrypted page to the main thread
        let len = (*mdl).byte_count as usize;
        let mut data = vec![0; len];
        data.extend_from_slice(core::ptr::slice_from_raw_parts((*mdl).start_va as *const u8, len).as_ref().expect("decrypted data should not be null"));
        let data_id = DATA_ID.with_borrow(|x| *x);
        let chunk_id = CHUNK_ID.with_borrow(|x| *x);
        CHUNK_ID.replace(chunk_id + 1);
        println!("{data_id}@{chunk_id}");
        DECRYPT_TX.send((data, data_id, chunk_id)).unwrap();

        MDL_LIST.with_borrow_mut(|list| list.remove(list.iter().position(|x| core::ptr::eq(x, mdl)).unwrap()));
    }
}

#[abi("system")]
/// # Safety
pub unsafe extern fn MmProbeAndLockPages(memory_descriptor_list: *mut MDL, _access_mode: KPROCESSOR_MODE, _operation: LOCK_OPERATION) {
    println!("MmProbeAndLockPages (MDL @ {:#X})", memory_descriptor_list as usize);
}

#[abi("system")]
/// # Safety
pub unsafe extern fn MmUnlockPages(memory_descriptor_list: *mut MDL) {
    unsafe {
        print!("MmUnlockPages (MDL @ {:#X})    ", memory_descriptor_list as usize);
        print!("MDL Flags Before {:#X}    ", (*memory_descriptor_list).mdl_flags);
        (*memory_descriptor_list).mdl_flags = 0;
        println!("MDL Flags After {:#X}", (*memory_descriptor_list).mdl_flags);
    }
}

#[abi("system")]
/// # Safety
pub unsafe extern fn MmLockPagableDataSection(address_within_section: ntdef::PVOID) -> ntdef::PVOID {
    println!("MmLockPagableDataSection ({:#X})", address_within_section as usize);
    address_within_section
}

#[abi("system")]
/// # Safety
pub unsafe extern fn MmMapLockedPagesSpecifyCache(_memory_descriptor_list: *mut MDL, _access_mode: KPROCESSOR_MODE, _cache_type: MEMORY_CACHING_TYPE) -> ntdef::PVOID {
    println!("MmMapLockedPagesSpecifyCache");
    0x0 as _
}

#[abi("system")]
/// # Safety
pub unsafe extern fn MmUnmapLockedPages(_base_address: ntdef::PVOID, _memory_descriptor_list: *mut MDL) {
    println!("MmUnmapLockedPages");
}
