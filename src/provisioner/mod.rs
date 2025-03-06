mod capacity;
mod lnvps;
mod network;
mod pricing;

pub use capacity::*;
pub use lnvps::*;
use lnvps_db::{DiskInterface, DiskType, VmCustomTemplate, VmTemplate};
pub use network::*;
pub use pricing::*;

pub trait Template {
    fn cpu(&self) -> u16;
    fn memory(&self) -> u64;
    fn disk_size(&self) -> u64;
    fn disk_type(&self) -> DiskType;
    fn disk_interface(&self) -> DiskInterface;
}

impl Template for VmTemplate {
    fn cpu(&self) -> u16 {
        self.cpu
    }

    fn memory(&self) -> u64 {
        self.memory
    }

    fn disk_size(&self) -> u64 {
        self.disk_size
    }

    fn disk_type(&self) -> DiskType {
        self.disk_type
    }

    fn disk_interface(&self) -> DiskInterface {
        self.disk_interface
    }
}

impl Template for VmCustomTemplate {
    fn cpu(&self) -> u16 {
        self.cpu
    }

    fn memory(&self) -> u64 {
        self.memory
    }

    fn disk_size(&self) -> u64 {
        self.disk_size
    }

    fn disk_type(&self) -> DiskType {
        self.disk_type
    }

    fn disk_interface(&self) -> DiskInterface {
        self.disk_interface
    }
}