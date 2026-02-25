use anyhow::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use config::{Config, File};
use hex::FromHex;
use lnvps_api_admin::settings::Settings;
use lnvps_db::{
    AdminDb, Company, DiskInterface, DiskType, EncryptedString, EncryptionContext, IpRange,
    IpRangeAllocationMode, LNVpsDbBase, LNVpsDbMysql, OsDistribution, PaymentMethod, PaymentType,
    User, UserSshKey, Vm, VmCostPlan, VmCostPlanIntervalType, VmCustomPricing, VmCustomTemplate,
    VmHost, VmHostDisk, VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
use log::info;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(about = "Generate comprehensive demo data for LNVPS", version, author)]
struct Args {
    /// Path to the config file
    #[clap(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let args = Args::parse();

    let settings: Settings = Config::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()?
        .try_deserialize()?;

    // Initialize encryption if configured
    if let Some(ref encryption_config) = settings.encryption {
        EncryptionContext::init_from_file(
            &encryption_config.key_file,
            encryption_config.auto_generate,
        )?;
        info!("Database encryption initialized");
    }

    // Connect database and migrate
    let db = LNVpsDbMysql::new(&settings.db).await?;
    clear_data(&db).await?;
    db.migrate().await?;

    info!("Generating demo data...");
    generate_demo_data(&db).await?;

    info!("Demo data generation completed successfully!");
    Ok(())
}

async fn clear_data(db: &LNVpsDbMysql) -> Result<()> {
    // Clear in proper order to respect foreign keys
    db.execute("drop database lnvps; create database lnvps; use lnvps;")
        .await?;
    Ok(())
}

async fn generate_demo_data(db: &LNVpsDbMysql) -> Result<()> {
    // 1. Create companies
    info!("Creating companies...");
    let companies = create_companies(db).await?;

    // 2. Create regions
    info!("Creating regions...");
    let regions = create_regions(db, &companies).await?;

    // 3. Create IP ranges
    info!("Creating IP ranges...");
    let ip_ranges = create_ip_ranges(db, &regions).await?;

    // 4. Create hosts
    info!("Creating hosts...");
    let hosts = create_hosts(db, &regions).await?;

    // 5. Create host disks
    info!("Creating host disks...");
    let disks = create_host_disks(db, &hosts).await?;

    // 6. Create OS images
    info!("Creating OS images...");
    let os_images = create_os_images(db).await?;

    // 7. Create cost plans
    info!("Creating cost plans...");
    let cost_plans = create_cost_plans(db).await?;

    // 8. Create templates
    info!("Creating VM templates...");
    let templates = create_vm_templates(db, &cost_plans, &regions).await?;

    // 9. Create custom pricing
    info!("Creating custom pricing...");
    let custom_pricing = create_custom_pricing(db, &regions).await?;

    // 10. Create custom templates
    info!("Creating custom templates...");
    let custom_templates = create_custom_templates(db, &custom_pricing).await?;

    // 11. Create users
    info!("Creating users...");
    let users = create_users(db).await?;

    // 12. Create SSH keys
    info!("Creating SSH keys...");
    let ssh_keys = create_ssh_keys(db, &users).await?;

    // 13. Create VMs
    info!("Creating VMs...");
    let vms = create_vms(
        db,
        &hosts,
        &users,
        &os_images,
        &templates,
        &custom_templates,
        &ssh_keys,
        &disks,
    )
    .await?;

    // 14. Create IP assignments (this ensures proper VM IDs are used)
    info!("Creating IP assignments...");
    create_ip_assignments(db, &vms, &ip_ranges).await?;

    // 15. Create payments
    info!("Creating payments...");
    create_payments(db, &vms).await?;

    info!("All demo data created successfully!");
    Ok(())
}

async fn create_companies(db: &LNVpsDbMysql) -> Result<Vec<Company>> {
    let companies = vec![
        Company {
            id: 0,                                      // Will be auto-generated
            created: years_ago(2) + Duration::days(15), // ~2 years ago
            name: "Lightning Cloud Systems".to_string(),
            email: Some("admin@lightningcloud.io".to_string()),
            phone: Some("+1-555-0101".to_string()),
            address_1: Some("123 Tech Plaza".to_string()),
            city: Some("San Francisco".to_string()),
            state: Some("CA".to_string()),
            postcode: Some("94105".to_string()),
            country_code: Some("USA".to_string()),
            tax_id: Some("US123456789".to_string()),
            base_currency: "USD".to_string(),
            address_2: None,
        },
        Company {
            id: 0,
            created: months_ago(18) + Duration::hours(9) + Duration::minutes(30), // ~1.5 years ago
            name: "Bitcoin Infrastructure Co".to_string(),
            email: Some("contact@btcinfra.com".to_string()),
            phone: Some("+44-20-1234-5678".to_string()),
            address_1: Some("456 Blockchain St".to_string()),
            city: Some("London".to_string()),
            state: Some("England".to_string()),
            postcode: Some("EC2A 4DP".to_string()),
            country_code: Some("GBR".to_string()),
            tax_id: Some("GB987654321".to_string()),
            base_currency: "GBP".to_string(),
            address_2: None,
        },
        Company {
            id: 0,
            created: months_ago(6) + Duration::hours(10) + Duration::minutes(15), // ~6 months ago
            name: "Nostr Hosting Ltd".to_string(),
            email: Some("hello@nostrhost.net".to_string()),
            phone: Some("+49-30-12345678".to_string()),
            address_1: Some("Bitcoinstraße 789".to_string()),
            city: Some("Berlin".to_string()),
            state: Some("Berlin".to_string()),
            postcode: Some("10115".to_string()),
            country_code: Some("DEU".to_string()),
            tax_id: Some("DE555777999".to_string()),
            base_currency: "EUR".to_string(),
            address_2: None,
        },
    ];

    let mut created_companies = Vec::new();
    for company in companies {
        let id = db.admin_create_company(&company).await?;

        let mut created_company = company;
        created_company.id = id;
        created_companies.push(created_company);
    }

    Ok(created_companies)
}

async fn create_regions(db: &LNVpsDbMysql, companies: &[Company]) -> Result<Vec<VmHostRegion>> {
    let regions_data = vec![
        ("US-East-1 (Virginia)", companies[0].id),
        ("US-West-1 (California)", companies[0].id),
        ("EU-Central-1 (Frankfurt)", companies[1].id),
        ("EU-West-1 (London)", companies[1].id),
        ("Asia-Pacific-1 (Singapore)", companies[2].id),
        ("Canada-Central-1 (Toronto)", companies[0].id),
        ("US-Central-1 (Chicago)", companies[0].id),
        ("EU-North-1 (Stockholm)", companies[2].id),
    ];

    let mut regions = Vec::new();
    for (name, company_id) in regions_data {
        let region = VmHostRegion {
            id: 0, // Will be auto-generated
            name: name.to_string(),
            enabled: true,
            company_id,
        };

        let id = db
            .admin_create_region(&region.name, region.enabled, region.company_id)
            .await?;

        let mut created_region = region;
        created_region.id = id;
        regions.push(created_region);
    }

    Ok(regions)
}

async fn create_ip_ranges(db: &LNVpsDbMysql, regions: &[VmHostRegion]) -> Result<Vec<IpRange>> {
    let ranges_data = vec![
        ("10.1.0.0/24", "10.1.0.1", regions[0].id),
        ("10.2.0.0/24", "10.2.0.1", regions[1].id),
        ("10.3.0.0/24", "10.3.0.1", regions[2].id),
        ("10.4.0.0/24", "10.4.0.1", regions[3].id),
        ("10.5.0.0/24", "10.5.0.1", regions[4].id),
        ("10.6.0.0/24", "10.6.0.1", regions[5].id),
        ("10.7.0.0/24", "10.7.0.1", regions[6].id),
        ("10.8.0.0/24", "10.8.0.1", regions[7].id),
    ];

    let mut ip_ranges = Vec::new();
    for (cidr, gateway, region_id) in ranges_data {
        let ip_range = IpRange {
            id: 0, // Will be auto-generated
            cidr: cidr.to_string(),
            gateway: gateway.to_string(),
            enabled: true,
            region_id,
            reverse_zone_id: None,
            access_policy_id: None,
            allocation_mode: IpRangeAllocationMode::Random,
            use_full_range: false,
        };

        let id = db.admin_create_ip_range(&ip_range).await?;

        let mut created_range = ip_range;
        created_range.id = id;
        ip_ranges.push(created_range);
    }

    Ok(ip_ranges)
}

async fn create_hosts(db: &LNVpsDbMysql, regions: &[VmHostRegion]) -> Result<Vec<VmHost>> {
    let hosts_data = vec![
        (
            VmHostKind::Proxmox,
            regions[0].id,
            "kvm-host-001",
            "http://10.1.0.10",
            32,
            134217728000u64,
            "token_kvm_001_abc123def456",
        ),
        (
            VmHostKind::Proxmox,
            regions[1].id,
            "kvm-host-002",
            "http://10.2.0.10",
            64,
            268435456000u64,
            "token_kvm_002_pqr678",
        ),
        (
            VmHostKind::Proxmox,
            regions[2].id,
            "kvm-host-003",
            "http://10.3.0.10",
            32,
            134217728000u64,
            "token_kvm_003_vwx234",
        ),
        (
            VmHostKind::Proxmox,
            regions[3].id,
            "kvm-host-004",
            "http://10.4.0.10",
            40,
            167772160000u64,
            "token_kvm_004_bcd890",
        ),
        (
            VmHostKind::Proxmox,
            regions[4].id,
            "kvm-host-005",
            "http://10.5.0.10",
            36,
            150323855360u64,
            "token_kvm_005_hij456",
        ),
        (
            VmHostKind::Proxmox,
            regions[5].id,
            "kvm-host-006",
            "http://10.6.0.10",
            32,
            134217728000u64,
            "token_kvm_006_nop012",
        ),
        (
            VmHostKind::Proxmox,
            regions[6].id,
            "kvm-host-007",
            "http://10.7.0.10",
            48,
            201326592000u64,
            "token_kvm_007_qrs345",
        ),
        (
            VmHostKind::Proxmox,
            regions[7].id,
            "kvm-host-008",
            "http://10.8.0.10",
            40,
            167772160000u64,
            "token_kvm_008_wxy901",
        ),
    ];

    let mut hosts = Vec::new();
    for (kind, region_id, name, ip, cpu, memory, api_token) in hosts_data {
        let host = VmHost {
            id: 0, // Will be auto-generated
            kind,
            region_id,
            name: name.to_string(),
            ip: ip.to_string(),
            cpu: cpu as u16,
            cpu_mfg: Default::default(),
            cpu_arch: Default::default(),
            cpu_features: Default::default(),
            memory,
            enabled: true,
            api_token: EncryptedString::new(api_token.to_string()),
            load_cpu: 1.0,
            load_memory: 1.0,
            load_disk: 1.0,
            vlan_id: None,
            mtu: None,
            ssh_user: None,
            ssh_key: None,
        };

        let id = db.create_host(&host).await?;

        let mut created_host = host;
        created_host.id = id;
        hosts.push(created_host);
    }

    Ok(hosts)
}

async fn create_host_disks(db: &LNVpsDbMysql, hosts: &[VmHost]) -> Result<Vec<VmHostDisk>> {
    let mut disks = Vec::new();

    // Create disks for each host
    for host in hosts {
        let disk_configs = vec![
            (
                "nvme0n1",
                2000000000000u64,
                DiskType::SSD,
                DiskInterface::PCIe,
            ),
            ("ssd0", 1000000000000u64, DiskType::SSD, DiskInterface::SATA),
        ];

        for (name, size, kind, interface) in disk_configs {
            let disk = VmHostDisk {
                id: 0, // Will be auto-generated
                host_id: host.id,
                name: name.to_string(),
                size,
                kind,
                interface,
                enabled: true,
            };

            let id = db.create_host_disk(&disk).await?;

            let mut created_disk = disk;
            created_disk.id = id;
            disks.push(created_disk);
        }
    }

    Ok(disks)
}

async fn create_os_images(db: &LNVpsDbMysql) -> Result<Vec<VmOsImage>> {
    let images_data = vec![
        (
            OsDistribution::Ubuntu,
            "server",
            "22.04",
            years_ago(3) + Duration::days(111),
            "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
        ),
        (
            OsDistribution::Ubuntu,
            "server",
            "24.04",
            months_ago(4),
            "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        ),
        (
            OsDistribution::Ubuntu,
            "server",
            "24.10",
            months_ago(2),
            "https://cloud-images.ubuntu.com/oracular/current/oracular-server-cloudimg-amd64.img",
        ),
        (
            OsDistribution::Debian,
            "standard",
            "12",
            months_ago(14),
            "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
        ),
        (
            OsDistribution::Debian,
            "standard",
            "13",
            months_ago(7),
            "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
        ),
        (
            OsDistribution::CentOS,
            "stream",
            "9",
            years_ago(2) + Duration::days(334),
            "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2",
        ),
        (
            OsDistribution::ArchLinux,
            "base",
            "2024.01",
            months_ago(7),
            "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
        ),
        (
            OsDistribution::ArchLinux,
            "base",
            "2025.08",
            days_ago(14),
            "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
        ),
    ];

    let mut os_images = Vec::new();
    for (distribution, flavour, version, release_date, url) in images_data {
        let os_image = VmOsImage {
            id: 0, // Will be auto-generated
            distribution,
            flavour: flavour.to_string(),
            version: version.to_string(),
            enabled: true,
            release_date,
            url: url.to_string(),
            default_username: Some("ubuntu".to_string()),
            sha2: None,
            sha2_url: None,
        };

        let id = db.admin_create_vm_os_image(&os_image).await?;

        let mut created_image = os_image;
        created_image.id = id;
        os_images.push(created_image);
    }

    Ok(os_images)
}

async fn create_cost_plans(db: &LNVpsDbMysql) -> Result<Vec<VmCostPlan>> {
    // Amounts are in smallest currency units: cents for fiat, millisats for BTC
    // BTC: 1 BTC = 100,000,000 sats = 100,000,000,000 millisats
    // 0.0005 BTC = 50,000 sats = 50,000,000 millisats
    let plans_data: Vec<(&str, u64, &str, i32, VmCostPlanIntervalType, DateTime<Utc>)> = vec![
        (
            "Nano BTC Plan",
            50_000_000, // 0.0005 BTC in millisats (~$50)
            "BTC",
            1,
            VmCostPlanIntervalType::Month,
            years_ago(2),
        ),
        (
            "Micro BTC Plan",
            100_000_000, // 0.001 BTC in millisats (~$100)
            "BTC",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(21),
        ),
        (
            "Small BTC Plan",
            200_000_000, // 0.002 BTC in millisats (~$200)
            "BTC",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(15),
        ),
        (
            "Medium BTC Plan",
            500_000_000, // 0.005 BTC in millisats (~$500)
            "BTC",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(12),
        ),
        (
            "Large BTC Plan",
            800_000_000, // 0.008 BTC in millisats (~$800)
            "BTC",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(8),
        ),
        (
            "XL BTC Plan",
            1_200_000_000, // 0.012 BTC in millisats (~$1200)
            "BTC",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(3),
        ),
        (
            "Basic USD Plan",
            500, // $5.00 in cents
            "USD",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(20),
        ),
        (
            "Standard USD Plan",
            1000, // $10.00 in cents
            "USD",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(16),
        ),
        (
            "Premium USD Plan",
            1500, // $15.00 in cents
            "USD",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(10),
        ),
        (
            "Enterprise USD Plan",
            2500, // $25.00 in cents
            "USD",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(4),
        ),
        (
            "Basic EUR Plan",
            450, // €4.50 in cents
            "EUR",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(9),
        ),
        (
            "Premium EUR Plan",
            1200, // €12.00 in cents
            "EUR",
            1,
            VmCostPlanIntervalType::Month,
            months_ago(1),
        ),
    ];

    let mut cost_plans = Vec::new();
    for (name, amount, currency, interval_amount, interval_type, created_date) in plans_data {
        let cost_plan = VmCostPlan {
            id: 0, // Will be auto-generated
            name: name.to_string(),
            created: created_date,
            amount,
            currency: currency.to_string(),
            interval_amount: interval_amount as u64,
            interval_type,
        };

        let id = db.insert_cost_plan(&cost_plan).await?;

        let mut created_plan = cost_plan;
        created_plan.id = id;
        cost_plans.push(created_plan);
    }

    Ok(cost_plans)
}

async fn create_vm_templates(
    db: &LNVpsDbMysql,
    cost_plans: &[VmCostPlan],
    regions: &[VmHostRegion],
) -> Result<Vec<VmTemplate>> {
    let mut templates = Vec::new();

    let templates_data = vec![
        (
            "Nano - 1vCPU 512MB",
            1,
            536870912u64,
            10737418240u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[0].id,
            regions[0].id,
            years_ago(2) + Duration::days(15),
        ),
        (
            "Micro - 1vCPU 1GB",
            1,
            1073741824u64,
            21474836480u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[1].id,
            regions[0].id,
            months_ago(21),
        ),
        (
            "Small - 2vCPU 2GB",
            2,
            2147483648u64,
            42949672960u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[2].id,
            regions[0].id,
            months_ago(15),
        ),
        (
            "Medium - 4vCPU 4GB",
            4,
            4294967296u64,
            85899345920u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[3].id,
            regions[1].id,
            months_ago(12),
        ),
        (
            "Large - 8vCPU 8GB",
            8,
            8589934592u64,
            171798691840u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[4].id,
            regions[1].id,
            months_ago(8),
        ),
        (
            "XL - 16vCPU 16GB",
            16,
            17179869184u64,
            343597383680u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[5].id,
            regions[2].id,
            months_ago(3),
        ),
        (
            "Basic US - 2vCPU 4GB",
            2,
            4294967296u64,
            85899345920u64,
            DiskType::SSD,
            DiskInterface::SATA,
            cost_plans[6].id,
            regions[0].id,
            months_ago(20),
        ),
        (
            "Standard US - 4vCPU 8GB",
            4,
            8589934592u64,
            171798691840u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[7].id,
            regions[1].id,
            months_ago(16),
        ),
        (
            "Premium US - 8vCPU 16GB",
            8,
            17179869184u64,
            343597383680u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[8].id,
            regions[6].id,
            months_ago(10),
        ),
        (
            "Enterprise - 32vCPU 64GB",
            32,
            68719476736u64,
            1099511627776u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[9].id,
            regions[5].id,
            months_ago(4),
        ),
        (
            "EU Basic - 2vCPU 4GB",
            2,
            4294967296u64,
            85899345920u64,
            DiskType::SSD,
            DiskInterface::SATA,
            cost_plans[10].id,
            regions[2].id,
            months_ago(9),
        ),
        (
            "EU Premium - 16vCPU 32GB",
            16,
            34359738368u64,
            687194767360u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            cost_plans[11].id,
            regions[3].id,
            months_ago(1),
        ),
    ];

    for (
        name,
        cpu,
        memory,
        disk_size,
        disk_type,
        disk_interface,
        cost_plan_id,
        region_id,
        created_date,
    ) in templates_data
    {
        let template = VmTemplate {
            id: 0, // Will be auto-generated
            name: name.to_string(),
            enabled: true,
            created: created_date,
            expires: None,
            cpu: cpu as u16,
            cpu_mfg: Default::default(),
            cpu_arch: Default::default(),
            cpu_features: Default::default(),
            memory,
            disk_size,
            disk_type,
            disk_interface,
            cost_plan_id,
            region_id,
            ..Default::default()
        };

        let id = db.insert_vm_template(&template).await?;

        let mut created_template = template;
        created_template.id = id;
        templates.push(created_template);
    }

    Ok(templates)
}

async fn create_custom_pricing(
    db: &LNVpsDbMysql,
    regions: &[VmHostRegion],
) -> Result<Vec<VmCustomPricing>> {
    // Costs are in smallest currency units per resource unit:
    // - cpu_cost: per CPU core per month
    // - memory_cost: per GB RAM per month
    // - ip4_cost: per IPv4 address per month
    // - ip6_cost: per IPv6 address per month
    // BTC: amounts in millisats, Fiat: amounts in cents
    let pricing_data: Vec<(
        &str,
        u64,
        &str,
        u64,
        u64,
        u64,
        u64,
        i32,
        i32,
        u64,
        u64,
        DateTime<Utc>,
    )> = vec![
        (
            "US-East Flex Pricing",
            regions[0].id,
            "BTC",
            5_000_000,  // cpu_cost: 0.00005 BTC = 5000 sats = 5,000,000 millisats per CPU
            250_000,    // memory_cost: 0.0000025 BTC = 250 sats = 250,000 millisats per GB
            10_000_000, // ip4_cost: 0.0001 BTC = 10000 sats = 10,000,000 millisats per IPv4
            5_000_000,  // ip6_cost: 0.00005 BTC = 5000 sats = 5,000,000 millisats per IPv6
            1,
            32,
            1073741824u64,
            137438953472u64,
            months_ago(18),
        ),
        (
            "EU-Central GDPR Compliant",
            regions[2].id,
            "EUR",
            14, // cpu_cost: €0.135 ≈ 14 cents per CPU
            1,  // memory_cost: €0.0007 ≈ 1 cent per GB (rounded up)
            5,  // ip4_cost: €0.045 ≈ 5 cents per IPv4
            2,  // ip6_cost: €0.0225 ≈ 2 cents per IPv6
            1,
            40,
            1073741824u64,
            171798691840u64,
            months_ago(14),
        ),
        (
            "Asia-Pacific Budget",
            regions[4].id,
            "USD",
            8, // cpu_cost: $0.08 = 8 cents per CPU
            1, // memory_cost: $0.00005 ≈ 0 cents (min 1)
            3, // ip4_cost: $0.03 = 3 cents per IPv4
            2, // ip6_cost: $0.015 ≈ 2 cents per IPv6
            1,
            24,
            1073741824u64,
            103079215104u64,
            months_ago(11),
        ),
        (
            "Canada Premium",
            regions[5].id,
            "USD",
            15, // cpu_cost: $0.15 = 15 cents per CPU
            1,  // memory_cost: $0.00008 ≈ 0 cents (min 1)
            5,  // ip4_cost: $0.05 = 5 cents per IPv4
            3,  // ip6_cost: $0.025 ≈ 3 cents per IPv6
            2,
            48,
            2147483648u64,
            206158430208u64,
            months_ago(7),
        ),
        (
            "EU-North Lightning",
            regions[7].id,
            "BTC",
            8_000_000,  // cpu_cost: 0.00008 BTC = 8000 sats = 8,000,000 millisats per CPU
            400_000,    // memory_cost: 0.000004 BTC = 400 sats = 400,000 millisats per GB
            15_000_000, // ip4_cost: 0.00015 BTC = 15000 sats = 15,000,000 millisats per IPv4
            8_000_000,  // ip6_cost: 0.00008 BTC = 8000 sats = 8,000,000 millisats per IPv6
            1,
            64,
            1073741824u64,
            274877906944u64,
            months_ago(5),
        ),
        (
            "US-Central Enterprise",
            regions[6].id,
            "USD",
            25, // cpu_cost: $0.25 = 25 cents per CPU
            1,  // memory_cost: $0.00012 ≈ 0 cents (min 1)
            8,  // ip4_cost: $0.08 = 8 cents per IPv4
            4,  // ip6_cost: $0.04 = 4 cents per IPv6
            4,
            128,
            8589934592u64,
            549755813888u64,
            months_ago(2),
        ),
    ];

    let mut custom_pricing = Vec::new();
    for (
        name,
        region_id,
        currency,
        cpu_cost,
        memory_cost,
        ip4_cost,
        ip6_cost,
        min_cpu,
        max_cpu,
        min_memory,
        max_memory,
        created_date,
    ) in pricing_data
    {
        let pricing = VmCustomPricing {
            id: 0, // Will be auto-generated
            name: name.to_string(),
            enabled: true,
            created: created_date,
            expires: None,
            region_id,
            currency: currency.to_string(),
            cpu_mfg: Default::default(),
            cpu_arch: Default::default(),
            cpu_features: Default::default(),
            cpu_cost,
            memory_cost,
            ip4_cost,
            ip6_cost,
            min_cpu: min_cpu as u16,
            max_cpu: max_cpu as u16,
            min_memory,
            max_memory,
        };

        let id = db.insert_custom_pricing(&pricing).await?;

        let mut created_pricing = pricing;
        created_pricing.id = id;
        custom_pricing.push(created_pricing);
    }

    Ok(custom_pricing)
}

async fn create_custom_templates(
    db: &LNVpsDbMysql,
    custom_pricing: &[VmCustomPricing],
) -> Result<Vec<VmCustomTemplate>> {
    let templates_data = vec![
        (
            2,
            4294967296u64,
            21474836480u64,
            DiskType::SSD,
            DiskInterface::PCIe,
            custom_pricing[0].id,
        ),
        (
            4,
            8589934592u64,
            107374182400u64,
            DiskType::SSD,
            DiskInterface::SATA,
            custom_pricing[1].id,
        ),
    ];

    let mut custom_templates = Vec::new();
    for (cpu, memory, disk_size, disk_type, disk_interface, pricing_id) in templates_data {
        let template = VmCustomTemplate {
            id: 0, // Will be auto-generated
            cpu: cpu as u16,
            memory,
            disk_size,
            disk_type,
            disk_interface,
            pricing_id,
            ..Default::default()
        };

        let id = db.insert_custom_vm_template(&template).await?;

        let mut created_template = template;
        created_template.id = id;
        custom_templates.push(created_template);
    }

    Ok(custom_templates)
}

async fn create_users(db: &LNVpsDbMysql) -> Result<Vec<User>> {
    // Using the first 20 hex pubkeys from the original data
    let users_data = vec![
        (
            "32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245",
            months_ago(20),
            "jb55@example.com",
        ),
        (
            "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2",
            months_ago(18),
            "jack@example.com",
        ),
        (
            "00000000827ffaa94bfea288c3dfce4422c794fbb96625b6b31e9049f729d700",
            months_ago(13),
            "cameri@example.com",
        ),
        (
            "04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9",
            months_ago(12),
            "odell@example.com",
        ),
        (
            "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93",
            months_ago(10),
            "dergigi@example.com",
        ),
        (
            "22aa81510ee63fe2b16cae16e0921f78e9ba9882e2868e7e63ad6d08ae9b5954",
            months_ago(8),
            "mrkukks@example.com",
        ),
        (
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
            years_ago(69),
            "fiatjaf@example.com",
        ),
        (
            "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c",
            years_ago(1),
            "vitorpamplona@example.com",
        ),
    ];

    let mut users = Vec::new();
    for (pubkey_hex, created, email) in users_data {
        let pubkey_bytes = Vec::from_hex(pubkey_hex)?;

        let user = User {
            id: 0, // Will be auto-generated
            pubkey: pubkey_bytes.clone(),
            created,
            email: EncryptedString::new(email.to_string()),
            email_verified: true,
            email_verify_token: String::new(),
            contact_nip17: true,
            contact_email: true,
            country_code: None,
            billing_name: None,
            billing_address_1: None,
            billing_address_2: None,
            billing_city: None,
            billing_state: None,
            billing_postcode: None,
            billing_tax_id: None,
            nwc_connection_string: None,
        };

        let pubkey_array: [u8; 32] = pubkey_bytes.as_slice().try_into()?;
        let id = db.upsert_user(&pubkey_array).await?;

        let mut created_user = user;
        created_user.id = id;
        db.update_user(&created_user).await?;
        users.push(created_user);
    }

    Ok(users)
}

async fn create_ssh_keys(db: &LNVpsDbMysql, users: &[User]) -> Result<Vec<UserSshKey>> {
    let mut ssh_keys = Vec::new();

    for (i, user) in users.iter().enumerate() {
        let name = format!("key-{}", i + 1);
        let key_data = format!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC{}... user{}@laptop",
            "x".repeat(400),
            i + 1
        ); // Simplified key data

        let ssh_key = UserSshKey {
            id: 0, // Will be auto-generated
            name: name.clone(),
            user_id: user.id,
            created: user.created,
            key_data: EncryptedString::new(key_data),
        };

        let id = db.insert_user_ssh_key(&ssh_key).await?;

        let mut created_key = ssh_key;
        created_key.id = id;
        ssh_keys.push(created_key);
    }

    Ok(ssh_keys)
}

async fn create_vms(
    db: &LNVpsDbMysql,
    hosts: &[VmHost],
    users: &[User],
    os_images: &[VmOsImage],
    templates: &[VmTemplate],
    custom_templates: &[VmCustomTemplate],
    ssh_keys: &[UserSshKey],
    disks: &[VmHostDisk],
) -> Result<Vec<Vm>> {
    let mut vms = Vec::new();

    // Create 20 regular VMs using templates with spread dates
    for i in 0..20 {
        let host = &hosts[i % hosts.len()];
        let user = &users[i % users.len()];
        let os_image = &os_images[i % os_images.len()];
        let template = &templates[i % templates.len()];
        let ssh_key = &ssh_keys[i % ssh_keys.len()];
        let disk = &disks[i % disks.len()];

        // Spread VMs across the last 18 months to today
        let created = match i {
            0..=2 => months_ago(18) + Duration::days(i as i64 * 10), // ~18 months ago
            3..=5 => months_ago(15) + Duration::days((i - 3) as i64 * 10), // ~15 months ago
            6..=8 => months_ago(12) + Duration::days((i - 6) as i64 * 10), // ~12 months ago
            9..=11 => months_ago(8) + Duration::days((i - 9) as i64 * 10), // ~8 months ago
            12..=14 => months_ago(5) + Duration::days((i - 12) as i64 * 10), // ~5 months ago
            15..=17 => months_ago(2) + Duration::days((i - 15) as i64 * 10), // ~2 months ago
            18 => days_ago(15),                                      // 15 days ago
            19 => days_ago(3),                                       // 3 days ago
            _ => days_ago(1),                                        // 1 day ago (fallback)
        };
        let expires = created + Duration::days(90);
        let mac_address = format!("02:00:00:01:00:{:02x}", i + 1);
        let ref_code = if i < 5 {
            Some(vec!["JACK2023", "DAMUS01", "ORANGE99", "NOSTR21", "SATS4ALL"][i].to_string())
        } else {
            None
        };

        let vm = Vm {
            id: 0, // Will be auto-generated
            host_id: host.id,
            user_id: user.id,
            image_id: os_image.id,
            template_id: Some(template.id),
            custom_template_id: None,
            ssh_key_id: ssh_key.id,
            created,
            expires,
            disk_id: disk.id,
            mac_address: mac_address.clone(),
            deleted: false,
            ref_code: ref_code.clone(),
            auto_renewal_enabled: false,
            disabled: false,
        };

        let id = db.insert_vm(&vm).await?;

        let mut created_vm = vm;
        created_vm.id = id;
        vms.push(created_vm);
    }

    // Create 5 custom VMs using custom templates
    for i in 0..5 {
        let host = &hosts[i % hosts.len()];
        let user = &users[i % users.len()];
        let os_image = &os_images[i % os_images.len()];
        let custom_template = &custom_templates[i % custom_templates.len()];
        let ssh_key = &ssh_keys[i % ssh_keys.len()];
        let disk = &disks[i % disks.len()];

        // Spread custom VMs across last 10 months
        let created = match i {
            0 => months_ago(10),
            1 => months_ago(7),
            2 => months_ago(4),
            3 => months_ago(1),
            4 => days_ago(5),
            _ => days_ago(1),
        };
        let expires = created + Duration::days(90);
        let mac_address = format!("02:00:00:02:00:{:02x}", i + 1);

        let vm = Vm {
            id: 0, // Will be auto-generated
            host_id: host.id,
            user_id: user.id,
            image_id: os_image.id,
            template_id: None,
            custom_template_id: Some(custom_template.id),
            ssh_key_id: ssh_key.id,
            created,
            expires,
            disk_id: disk.id,
            mac_address: mac_address.clone(),
            deleted: false,
            ref_code: None,
            auto_renewal_enabled: false,
            disabled: false,
        };

        let id = db.insert_vm(&vm).await?;

        let mut created_vm = vm;
        created_vm.id = id;
        vms.push(created_vm);
    }

    Ok(vms)
}

async fn create_ip_assignments(db: &LNVpsDbMysql, vms: &[Vm], ip_ranges: &[IpRange]) -> Result<()> {
    for (i, vm) in vms.iter().enumerate() {
        let ip_range = &ip_ranges[i % ip_ranges.len()];
        let ip = format!("10.{}.0.{}", (i % 8) + 1, (i % 250) + 10);

        let assignment = VmIpAssignment {
            id: 0, // Will be auto-generated
            vm_id: vm.id,
            ip_range_id: ip_range.id,
            ip,
            deleted: false,
            arp_ref: None,
            dns_forward: None,
            dns_forward_ref: None,
            dns_reverse: None,
            dns_reverse_ref: None,
        };

        db.insert_vm_ip_assignment(&assignment).await?;
    }

    Ok(())
}

async fn create_payments(db: &LNVpsDbMysql, vms: &[Vm]) -> Result<()> {
    for (i, vm) in vms.iter().enumerate() {
        let payment_id = format!("{:064x}", i + 1); // Simple hex ID
        let payment_method = match i % 3 {
            0 => PaymentMethod::Lightning,
            1 => PaymentMethod::Revolut,
            _ => PaymentMethod::Paypal,
        };
        let payment_type = PaymentType::Renewal;
        let amount = match payment_method {
            PaymentMethod::Lightning => 500000 + (i as u64 * 100000), // Lightning in sats (0.005-0.025 BTC range)
            _ => 500 + (i as u64 * 50), // Fiat in cents ($5.00-$15.00 range)
        };
        let currency = match payment_method {
            PaymentMethod::Lightning => "BTC",
            PaymentMethod::Revolut => "EUR",
            _ => "USD",
        };
        let external_data = match payment_method {
            PaymentMethod::Lightning => {
                format!(r#"{{"bolt11":"lnbc{}u{}..."}}"#, amount / 100, i + 1)
            }
            PaymentMethod::Revolut => format!(r#"{{"revolut_payment_id":"rev_{:03}"}}"#, i + 1),
            _ => format!(r#"{{"paypal_order_id":"pp_{:03}"}}"#, i + 1),
        };
        let external_id = format!("ext_{}", i + 1);
        let rate = match payment_method {
            PaymentMethod::Lightning => 95000.0 + (i as f32 * 1000.0), // BTC/USD rate (~$95k-105k)
            PaymentMethod::Revolut => 0.85 + (i as f32 * 0.01),        // EUR/USD rate
            _ => 1.0,                                                  // USD base rate
        };

        let payment_id_bytes = hex::decode(&payment_id)?;
        let payment = VmPayment {
            id: payment_id_bytes,
            vm_id: vm.id,
            created: vm.created,
            expires: vm.created + Duration::hours(1),
            amount,
            external_data: EncryptedString::new(external_data),
            time_value: 7776000,
            is_paid: true,
            rate,
            currency: currency.to_string(),
            payment_method,
            external_id: Some(external_id),
            payment_type,
            tax: 0,
            processing_fee: 0,
            upgrade_params: None,
            paid_at: Some(vm.created), // Demo data: assume paid immediately
        };

        db.insert_vm_payment(&payment).await?;
    }

    Ok(())
}

fn days_ago(days: i64) -> DateTime<Utc> {
    Utc::now() - Duration::days(days)
}

fn months_ago(months: i64) -> DateTime<Utc> {
    Utc::now() - Duration::days(months * 30)
}

fn years_ago(years: i64) -> DateTime<Utc> {
    Utc::now() - Duration::days(years * 365)
}
