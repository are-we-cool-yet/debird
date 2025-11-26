//! Faking exports/imports.

use std::{collections::{HashMap, HashSet}, fs::File, io::Write, path::Path, process::Command};

use crate::{error, util::Imports};

/// Fake exports of imported libraries
pub fn smuggle(path: &Path, imports: &Imports) -> error::Result<()> {
    let mut map = HashMap::new();
    for (name, (dll, _)) in imports.iter() {
        if !map.contains_key(dll) {
            map.try_insert(dll.to_string(), HashSet::new()).unwrap();
        }

        map.get_mut(dll).unwrap()
            .insert(name.to_string());
    }

    for (dll, exports) in map.iter() {
        let mut source = String::new();
        source.push_str(r#"
        #![crate_name = "fake_export"]
        "#);
        for export in exports {
            source.push_str(&gen_empty_fn(export));
        }

        let temp_path = path.join(dll.to_owned() + ".rs");
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(source.as_bytes())?;

        let mut command = Command::new("rustc");
        let child_output = command
            .args(["--color", "always"])
            .args(["--target", "x86_64-pc-windows-msvc"])
            .args(["--crate-type", "cdylib"])
            .args(["-o", path.join(dll).to_string_lossy().as_ref()])
            .arg(&*temp_path.to_string_lossy())
            .output()?;
        println!("{dll}");
        println!("{}", String::from_utf8_lossy(&child_output.stderr));
        println!("{}", String::from_utf8_lossy(&child_output.exit_ok()?.stdout));
    }

    Ok(())
}

fn gen_empty_fn(name: &str) -> String {
    r#"
    #[export_name = ""#.to_owned() + name + r#""]
    #[allow(non_snake_case)]
    pub extern "system" fn "# + name + r#"_FAKE() -> *mut ::std::ffi::c_void {
        unsafe { ::std::mem::transmute::<extern "system" fn() -> *mut ::std::ffi::c_void, *mut ::std::ffi::c_void>("# + name + r#"_FAKE) }
    }
    "#
}

