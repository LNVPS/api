pub enum DiskType {
    SSD,
    HDD,
}

pub struct VMSpec {
    pub cpu: u16,
    pub memory: u64,
    pub disk: u64,
    pub disk_type: DiskType,
}
