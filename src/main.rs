#![feature(map_try_insert)]
#![feature(exit_status_error)]

use std::{cell::RefCell, ffi, ops::Deref, path::{Path, PathBuf}, str::FromStr, sync::{LazyLock, mpsc}, thread::{self}, time::Duration};
use error::Error;
use pelite::FileMap;
use pelite::pe64::*;
use pretty_hex::config_hex;
use winapi::shared::minwindef::HMODULE;

use crate::{hook::Hooks, target::TargetDriver, util::from_base};

pub mod constants;
pub mod error;
pub mod hook;
pub mod util;
pub mod types;
pub mod target;
pub mod analyze;
pub mod patch;

thread_local! {
    pub static DECRYPT_RX: RefCell<Option<mpsc::Receiver<types::DecryptMessage>>> = const { RefCell::new(None) };
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
        if Path::new(&args[1]).exists() {
            &args[1]
        } else {
            println!("Current Directory: {}", std::env::current_dir()?.display());
            panic!("{} not found! Read the directions in README.md.", &args[1]);
        }
    )?;
    let mut data_dir = PathBuf::from(lib_path.parent().unwrap().ancestors().next().expect("path should not be in root folder (path should have ancestor folder)"));
    data_dir.push("data");
    if !data_dir.try_exists()? {
        println!("a {:?}", lib_path);
        println!("a {:?}", data_dir);
        std::fs::create_dir(data_dir.clone())?;
    }

    // Do some static analysis
    let lib_name = lib_path.file_name().expect("file name should be valid").to_string_lossy();
    println!("Analyzing {}", lib_name);
    let file_map = FileMap::open(&lib_path).expect("failed to open file map");
    let pe_file = PeFile::from_bytes(&file_map).expect("failed to open PE file, is this 64-bit?");
    let image_base = pe_file.optional_header().ImageBase as usize;
    let target_driver = TargetDriver::from_str(&lib_name)?;
    let analysis = match target_driver {
        TargetDriver::CLIPSP => analyze::clipsp(&lib_path, pe_file)?,
    };
    println!("Analyzed: {analysis:?}");

    // Now emulate the driver to decrypt and extract the code
    println!("Emulating {}", lib_name);

    unsafe {
        let lib = libloading::os::windows::Library::load_with_flags(&analysis.patched_path, constants::DONT_RESOLVE_DLL_REFERENCES)?;
        let handle = lib.into_raw();
        let mut hooks = Hooks::new(handle as HMODULE)?;

        // hook ntoskrnl functions
        create_hooks! { hooks:
            MmChangeImageProtection;
            IoAllocateMdl;
            IoFreeMdl;
            MmProbeAndLockPages;
            MmUnlockPages;
            MmLockPagableDataSection;
            MmMapLockedPagesSpecifyCache;
            MmUnmapLockedPages;
        };
        hooks.hook_unused_as_dummies()?;

        let _ = DECRYPT_TX.deref();

        let thread_handle = thread::spawn(move || {
            // Call decryption functions
            for &(const_data, rw_data, decrypt_fn_addr, data_id) in constants::DATA.iter() {
                println!("Data ID: {data_id:#X}");
                hook::DATA_ID.set(data_id);
                hook::CHUNK_ID.set(0);
                let rw_data_ptr = (from_base(rw_data, image_base) as *mut ffi::c_void).byte_offset(handle);
                let const_data_ptr = (from_base(const_data, image_base) as *mut winapi::ctypes::__int64).byte_offset(handle);
                if *((const_data_ptr.byte_offset(0x50)) as *mut winapi::shared::minwindef::DWORD) & 1 == 0 {
                    println!("Oops! Something is wrong with the Const Data provided. 0x{:X}", const_data);
                    println!("const_data + 0x50    0x{:X}", const_data_ptr.byte_offset(0x50) as usize);
                    println!("*(DWORD *)(const_data + 0x50)    0x{:X}", *(const_data_ptr.byte_offset(0x50) as *mut winapi::shared::minwindef::DWORD));
                    println!("*(DWORD *)(const_data + 0x50) & 1    0x{:X}", *(const_data_ptr.byte_offset(0x50) as *mut winapi::shared::minwindef::DWORD) & 1);
                }
                let decrypt_fn_ptr = (from_base(decrypt_fn_addr, image_base) as *mut ffi::c_void).byte_offset(handle);
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

        // unload library
        let lib = libloading::os::windows::Library::from_raw(handle);
        lib.close()?;
    }

    Ok(())
}
