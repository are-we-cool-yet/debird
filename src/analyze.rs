use std::{collections::HashMap, fs::File, os::windows::fs::FileExt, path::{Path, PathBuf}};

use pelite::{pattern, pe64::*};

use crate::{error, hook};

#[derive(Debug)]
pub struct Analysis {
    pub patched_path: PathBuf,
}

pub fn clipsp(lib_path: &Path, pe_file: PeFile) -> error::Result<Analysis> {
    let mut patches = HashMap::new();
    // The contents of the true `DriverEntry` function.
    // For whatever reason, CLIPSP.SYS has more than one `DriverEntry` function,
    // and this one is called upon attempting to load it. We want it to return
    // successfully.
    patches.insert("B8 01 00 00 C0 C3", hook::CANCEL_DRIVER_ENTRY);

    Ok(Analysis {
        patched_path: patch_driver(lib_path, &pe_file, patches)?
    })
}

// TODO: cache patches? would only be necessary if users are constantly calling debird
fn patch_driver(lib_path: &Path, pe_file: &PeFile, patches: HashMap<&str, &[u8]>) -> error::Result<PathBuf> {
    // scan for patch targets
    let scanner = pe_file.scanner();
    let patches = patches.into_iter()
        .map(|(pat, patch)| {
            let pattern = pattern::parse(pat)?;
            let mut save = [0u32; 1];
            let mut matches = scanner.matches(&pattern, 0 .. pe_file.optional_header().SizeOfImage);

            if matches.next(save.as_mut_slice()) {
                println!("Found patch `{}` @ {:#X}", pat, save[0]);
                Ok((pe_file.rva_to_file_offset(save[0])? as u64, patch))
            } else {
                Err(pattern.into())
            }
        }).collect::<Result<Vec<_>, error::Error>>()?;

    // create and fill new patched driver file
    let patched_path = lib_path.with_added_extension("patched");
    let mut lib_file = File::open(lib_path)?;
    let mut patched_file = File::create_new(&patched_path).or(File::create(&patched_path))?;
    std::io::copy(&mut lib_file, &mut patched_file)?;

    // patch driver
    for (location_in_file, patch) in patches {
        assert_eq!(patched_file.seek_write(patch, location_in_file)?, patch.len());
    }

    Ok(patched_path)
}
