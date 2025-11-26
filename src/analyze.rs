use std::path::{Path, PathBuf};

use pelite::pe64::*;

use crate::{error, hook, patch::Patcher};

#[derive(Debug)]
pub struct Analysis {
    pub patched_path: PathBuf,
}

pub fn clipsp(lib_path: &Path, pe_file: PeFile) -> error::Result<Analysis> {
    let mut patcher = Patcher::new(lib_path, &pe_file);

    // The contents of the true `DriverEntry` function.
    // For whatever reason, CLIPSP.SYS has more than one `DriverEntry` function,
    // and this one is called upon attempting to load it. We want it to return
    // successfully.
    patcher.patch("B8 01 00 00 C0 C3", hook::CANCEL_DRIVER_ENTRY)?;

    // Set 0x2000 File is DLL
    // TODO: move this elsewhere since we don't need it for CLIPSP but might for something else in the future
    // patcher.patch_procedural(&|pe_file, file| {
    //     let mut flags = pe_file.optional_header().DllCharacteristics;
    //     println!("{:08X}", flags);
    //     let pattern = pattern::parse(&format!("{flags:X}"))?;
    //     let mut save = [0; 1];
    //     let mut matches = pe_file.scanner().matches(&pattern, pe_file.headers().image_range());
    //     if matches.next(&mut save) {
    //         let mut_file = file.write().expect("poisoned lock");
    //         flags |= 0x2000; // add File is DLL flag
    //         mut_file.seek_write(&flags.to_le_bytes(), pe_file.rva_to_file_offset(save[0])? as u64)?;
    //         Ok(())
    //     } else {
    //         Err(error::Error::PatchNotFound(pattern))
    //     }
    // })?;

    // Extract read-write/const data and location of decryption functions

    Ok(Analysis {
        patched_path: patcher.patch_driver()?
    })
}

