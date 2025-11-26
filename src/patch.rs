use std::{collections::HashMap, fs::File, os::windows::fs::FileExt, path::{Path, PathBuf}, sync::{Arc, RwLock}};

use pelite::{pattern, pe64::{Pe, PeFile}};

use crate::error;

pub struct Patcher<'a> {
    lib_path: &'a Path,
    pe_file: &'a PeFile<'a>,
    patches: HashMap<&'a str, &'a [u8]>,
    procedural_patches: Vec<&'a dyn Fn(&'a PeFile<'a>, Arc<RwLock<File>>) -> error::Result<()>>,
}

impl<'a> Patcher<'a> {
    pub fn new(lib_path: &'a Path, pe_file: &'a PeFile<'a>) -> Self {
        Self {
            lib_path,
            pe_file,
            patches: HashMap::new(),
            procedural_patches: Vec::new(),
        }
    }

    /// Define a declarative patch
    pub fn patch(&mut self, pattern: &'a str, patch: &'a [u8]) -> error::Result<()> {
        self.patches.insert(pattern, patch);
        Ok(())
    }

    /// Define a manual, procedural patch
    pub fn patch_procedural(&mut self, patch: &'a dyn Fn(&'a PeFile<'a>, Arc<RwLock<File>>) -> error::Result<()>) -> error::Result<()> {
        self.procedural_patches.push(patch);
        Ok(())
    }

    /// Apply all patches
    pub fn patch_driver(self) -> error::Result<PathBuf> {
        // scan for patch targets
        let scanner = self.pe_file.scanner();
        let patches = self.patches.into_iter()
            .map(|(pat, patch)| {
                let pattern = pattern::parse(pat)?;
                let mut save = [0u32; 1];
                let mut matches = scanner.matches(&pattern, self.pe_file.headers().image_range());

                if matches.next(save.as_mut_slice()) {
                    println!("Found patch `{}` @ {:#X}", pat, save[0]);
                    Ok((self.pe_file.rva_to_file_offset(save[0])? as u64, patch))
                } else {
                    Err(pattern.into())
                }
            }).collect::<Result<Vec<_>, error::Error>>()?;

        // create and fill new patched driver file
        let patched_path = self.lib_path.with_added_extension("patched");
        let mut lib_file = File::open(self.lib_path)?;
        let patched_file = Arc::new(RwLock::new(File::create_new(&patched_path).or(File::create(&patched_path))?));

        {
            // mut_patched_file exists because rust jank
            // we want a mutable reference that also somehow lives less than the Patcher struct
            let mut mut_patched_file = patched_file.write().expect("poisoned lock");
            std::io::copy(&mut lib_file, &mut *mut_patched_file)?;

            // patch driver
            for (location_in_file, patch) in patches {
                assert_eq!(mut_patched_file.seek_write(patch, location_in_file)?, patch.len());
            }
        }

        // apply procedural patches
        for patch in self.procedural_patches {
            patch(&self.pe_file, patched_file.clone())?;
        }

        Ok(patched_path)
    }
}

