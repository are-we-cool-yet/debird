use std::{cell::RefCell, ffi, ops::Deref, path::{Path, PathBuf}, sync::{mpsc, LazyLock}, thread::{self}, time::Duration};
use error::Error;
use minhook::MinHook;
use pretty_hex::config_hex;
use util::offset_addr;

pub mod constants;
pub mod error;
pub mod hook;
pub mod util;
pub mod types;

thread_local! {
    pub static DECRYPT_RX: RefCell<Option<mpsc::Receiver<types::DecryptMessage>>> = RefCell::new(None);
}

pub static DECRYPT_TX: LazyLock<mpsc::SyncSender<types::DecryptMessage>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::sync_channel(constants::DATA.len() * 3);
    if thread::current().name().is_some() {
        DECRYPT_RX.set(Some(rx));
    }
    tx
});

fn main() -> Result<(), Error> {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() != 1 {
        println!("Usage:\n\
debird <path-to-driver>");
    }

    // SAFETY: It is assumed that the library is safe to load and that the platform supports calling functions via DLL offset.
    // It also assumes that Microsoft hasn't changed anything. If these conditions aren't met, god help you.

    let lib_path = std::fs::canonicalize(
        if Path::new(&args[0]).exists() {
            &args[0]
        } else {
            println!("Current Directory: {}", std::env::current_dir()?.display());
            panic!("{} not found! Read the directions in README.md.", &args[0]);
        }
    )?;
    let mut data_dir = PathBuf::from(lib_path.ancestors().next().expect("path should not be in root folder (path should have ancestor folder)"));
    data_dir.push("data");
    if !data_dir.try_exists()? {
        std::fs::create_dir(data_dir.clone())?;
    }

    unsafe {
        println!("Loading {}", lib_path.file_name().expect("file name should be valid").to_string_lossy().to_string());
        let lib = libloading::os::windows::Library::load_with_flags(&lib_path, libloading::os::windows::LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)?;
        let handle = lib.into_raw();

        // hook ntoskrnl functions
        create_hooks_with_handle! { handle:
            MmChangeImageProtection;
            IoAllocateMdl;
            IoFreeMdl;
            MmProbeAndLockPages;
            MmUnlockPages;
            MmLockPagableDataSection;
            MmMapLockedPagesSpecifyCache;
            MmUnmapLockedPages;
        };

        MinHook::enable_all_hooks()?;

        let _ = DECRYPT_TX.deref();

        let thread_handle = thread::spawn(move || {
            // Call decryption functions
            for &(const_data, rw_data, decrypt_fn_addr, data_id) in constants::DATA.iter() {
                println!("{data_id}");
                hook::DATA_ID.set(data_id);
                hook::CHUNK_ID.set(0);
                let rw_data_ptr: *mut ffi::c_void = offset_addr(rw_data, handle);
                let const_data_ptr = offset_addr::<winapi::ctypes::__int64>(const_data, handle);
                if *((const_data_ptr.byte_offset(0x50)) as *mut winapi::shared::minwindef::DWORD) & 1 == 0 {
                    println!("Oops! Something is wrong with the Const Data provided. 0x{:X}", const_data);
                    println!("const_data + 0x50    0x{:X}", const_data_ptr.byte_offset(0x50) as usize);
                    println!("*(DWORD *)(const_data + 0x50)    0x{:X}", *(const_data_ptr.byte_offset(0x50) as *mut winapi::shared::minwindef::DWORD));
                    println!("*(DWORD *)(const_data + 0x50) & 1    0x{:X}", *(const_data_ptr.byte_offset(0x50) as *mut winapi::shared::minwindef::DWORD) & 1);
                }
                let decrypt_fn_ptr = offset_addr(decrypt_fn_addr, handle);
                let decrypt_fn = std::mem::transmute::<*mut ffi::c_void, types::WarbirdDecrypt>(decrypt_fn_ptr);
                println!("Decrypting rw_data (0x{rw_data:X}) and const_data (0x{const_data:X}) w/ 0x{decrypt_fn_addr:X}");
                let decrypted = decrypt_fn(const_data_ptr as _, rw_data_ptr as *mut _);
                println!("Error Code: 0x{decrypted:X}\n");
            }
        });

        thread_handle.join().expect("couldn't join thread");

        // Receive decrypted data
        let mut datas = vec![];
        loop {
            let data = DECRYPT_RX.with_borrow(|rx| {
                rx.as_ref().unwrap().recv_timeout(Duration::from_millis(125))
            });
            if let Ok(data) = data {
                datas.push(data);
            } else {
                break
            }
        }

        datas
            .iter()
            .for_each(|(data, data_id, chunk_id)| {
                if constants::PRINT_DATA {
                    println!("{data_id}@{chunk_id} received!");
                    println!("{}", config_hex(data, constants::HEX_CONFIG));
                }
            });

        datas
            .iter()
            .try_for_each::<_, Result<_, Error>>(|(data, data_id, chunk_id)| {
                let mut data_file_path = data_dir.clone();
                data_file_path.push(format!("data_{data_id}@{chunk_id}.bin"));
                std::fs::write(data_file_path, data)?;
                Ok(())
            })?;

        // uninitialize hooks
        MinHook::disable_all_hooks()?;
        MinHook::uninitialize();

        // unload library
        let lib = libloading::os::windows::Library::from_raw(handle);
        lib.close()?;
    }

    Ok(())
}
