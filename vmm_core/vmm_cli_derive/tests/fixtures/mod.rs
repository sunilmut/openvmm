// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[derive(Debug, PartialEq, vmm_cli::KeyValueArgs)]
pub struct Common {
    /// Required byte size.
    pub size: u64,
    #[kv(key = "count", default = 4)]
    pub queues: u16,
    #[kv(default)]
    pub label: String,
    pub serial: Option<String>,
    /// Allow read-only access.
    /// Never writes guest data.
    #[kv(flag)]
    pub readonly: bool,
    #[kv(flag)]
    pub cache: Option<bool>,
    #[kv(flag, present = 8, absent = 3)]
    pub policy: u8,
}

#[derive(Debug, PartialEq, vmm_cli::KeyValueGroup)]
pub enum Backend {
    /// Use guest memory.
    #[kv(default, key = "mem")]
    Memory,
    #[kv(key = "host-file")]
    File(String),
    RawDevice(Option<u16>),
}

#[derive(Debug, PartialEq, vmm_cli::KeyValueArgs)]
pub struct Disk {
    #[kv(positional)]
    pub path: String,
    #[kv(flatten)]
    pub common: Common,
    #[kv(flatten)]
    pub backend: Backend,
}

#[derive(Debug, PartialEq, vmm_cli::KeyValueArgs)]
pub struct FlatOnly {
    #[kv(flatten)]
    pub common: Common,
}

#[derive(Debug, PartialEq, vmm_cli::KeyValueGroup)]
pub enum Boot {
    Uefi,
    Grub(String),
}

#[derive(Debug, PartialEq, vmm_cli::KeyValueArgs)]
pub struct RequiredBoot {
    #[kv(flatten)]
    pub boot: Boot,
}

#[derive(Debug, PartialEq, vmm_cli::KeyValueArgs)]
pub struct Empty {}
