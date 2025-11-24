use std::{fs::File, os::windows::fs::FileExt, path::{Path, PathBuf}};

use pelite::{pattern, pe64::*};

use crate::{error, hook};

#[derive(Debug)]
pub struct Analysis {
    pub patched_path: PathBuf,
}

pub fn clipsp(lib_path: &Path, pe_file: PeFile) -> error::Result<Analysis> {
    let scanner = pe_file.scanner();

    // The contents of the true `DriverEntry` function.
    // For whatever reason, CLIPSP.SYS has more than one `DriverEntry` function,
    // and this one is called upon attempting to load it. We want it to return
    // successfully.
    let driver_entry_pattern = pattern::parse("B8 01 00 00 C0 C3").unwrap();
    let mut save = [0; 4];
    let range = 0 .. pe_file.optional_header().SizeOfImage;
    println!("Searching {:#X?}", range);
    let mut matches = scanner.matches(&driver_entry_pattern, range);
    let first_match = matches.next(&mut save);
    if first_match {
        println!("Found anti-emulation DriverEntry @ {:#X}", save[0]);
    } else {
        panic!("Anti-emulation DriverEntry function not found for CLIPSP.SYS!");
    }
    let driver_entry_in_file = pe_file.rva_to_file_offset(save[0])? as u64;
    let patched_path = lib_path.with_added_extension("patched");
    let mut lib_file = File::open(lib_path)?;
    let mut patched_file = File::open(&patched_path).or(File::create_new(&patched_path))?;
    std::io::copy(&mut lib_file, &mut patched_file)?;
    assert_eq!(patched_file.seek_write(hook::CANCEL_DRIVER_ENTRY, driver_entry_in_file)?, hook::CANCEL_DRIVER_ENTRY.len());
    Ok(Analysis { patched_path })
}
