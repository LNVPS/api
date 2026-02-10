insert
ignore into vm_host_region(id,name,enabled) values(1,"uat",1);
insert
ignore into vm_host(id,kind,region_id,name,ip,cpu,memory,enabled,api_token)
values(1, 0, 1, "lab", "https://10.100.1.5:8006", 4, 4096*1024, 1, "root@pam!tester=c82f8a57-f876-4ca4-8610-c086d8d9d51c");
insert
ignore into vm_host_disk(id,host_id,name,size,kind,interface,enabled)
values(1,1,"local-zfs",1000*1000*1000*1000, 0, 0, 1);
insert
ignore into vm_os_image(id,distribution,flavour,version,enabled,url,release_date)
values(1, 0,"Server","24.04",1,"https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img","2024-04-25");
insert
ignore into vm_os_image(id,distribution,flavour,version,enabled,url,release_date)
values(2, 0,"Server","22.04",1,"https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img","2022-04-21");
insert
ignore into vm_os_image(id,distribution,flavour,version,enabled,url,release_date)
values(3, 0,"Server","20.04",1,"https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img","2020-04-23");
insert
ignore into vm_os_image(id,distribution,flavour,version,enabled,url,release_date)
values(4, 1,"Server","12",1,"https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.raw","2023-06-10");
insert
ignore into vm_os_image(id,distribution,flavour,version,enabled,url,release_date)
values(5, 1,"Server","11",1,"https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.raw","2021-08-14");
insert
ignore into ip_range(id,cidr,enabled,region_id,gateway)
values(1,"10.100.1.128/25",1,1,"10.100.1.1/24");
insert
ignore into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type)
values(1,"tiny_monthly",2,"EUR",1,1);
insert
ignore into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type)
values(2,"small_monthly",4,"EUR",1,1);
insert
ignore into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type)
values(3,"medium_monthly",8,"EUR",1,1);
insert
ignore into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type)
values(4,"large_monthly",17,"EUR",1,1);
insert
ignore into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type)
values(5,"xlarge_monthly",30,"EUR",1,1);
insert
ignore into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type)
values(6,"xxlarge_monthly",45,"EUR",1,1);
insert
ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id)
values(1,"Tiny",1,1,1024*1024*1024*1,1024*1024*1024*40,1,2,1,1);
insert
ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id)
values(2,"Small",1,2,1024*1024*1024*2,1024*1024*1024*80,1,2,2,1);
insert
ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id)
values(3,"Medium",1,4,1024*1024*1024*4,1024*1024*1024*160,1,2,3,1);
insert
ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id)
values(4,"Large",1,8,1024*1024*1024*8,1024*1024*1024*400,1,2,4,1);
insert
ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id)
values(5,"X-Large",1,12,1024*1024*1024*16,1024*1024*1024*800,1,2,5,1);
insert
ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id)
values(6,"XX-Large",1,20,1024*1024*1024*24,1024*1024*1024*1000,1,2,6,1);

-- Available IP Space for sale
insert
ignore into available_ip_space(id,cidr,min_prefix_size,max_prefix_size,registry,external_id,is_available,is_reserved,metadata)
values(1,"192.0.2.0/24",32,24,0,"ARIN-2024-001",1,0,'{"upstream":"ExampleISP","asn":65000}');

insert
ignore into available_ip_space(id,cidr,min_prefix_size,max_prefix_size,registry,external_id,is_available,is_reserved,metadata)
values(2,"198.51.100.0/22",26,22,0,"ARIN-2024-002",1,0,'{"upstream":"ExampleISP","asn":65000}');

insert
ignore into available_ip_space(id,cidr,min_prefix_size,max_prefix_size,registry,external_id,is_available,is_reserved,metadata)
values(3,"2001:db8::/29",48,32,1,"RIPE-2024-001",1,0,'{"upstream":"ExampleISP","asn":65000}');

-- IP Space Pricing
-- Pricing for 192.0.2.0/24
insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(1,1,32,500,"USD",1000); -- /32 single IP: $5/mo, $10 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(2,1,24,15000,"USD",5000); -- /24 (256 IPs): $150/mo, $50 setup

-- Pricing for 198.51.100.0/22
insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(3,2,26,4000,"USD",2000); -- /26 (64 IPs): $40/mo, $20 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(4,2,25,7500,"USD",3000); -- /25 (128 IPs): $75/mo, $30 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(5,2,24,14000,"USD",5000); -- /24 (256 IPs): $140/mo, $50 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(6,2,23,26000,"USD",8000); -- /23 (512 IPs): $260/mo, $80 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(7,2,22,50000,"USD",15000); -- /22 (1024 IPs): $500/mo, $150 setup

-- Pricing for IPv6 2001:db8::/29
insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(8,3,48,2000,"USD",5000); -- /48 (for end sites): $20/mo, $50 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(9,3,44,5000,"USD",10000); -- /44: $50/mo, $100 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(10,3,40,12000,"USD",20000); -- /40: $120/mo, $200 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(11,3,36,25000,"USD",35000); -- /36: $250/mo, $350 setup

insert
ignore into ip_space_pricing(id,available_ip_space_id,prefix_size,price_per_month,currency,setup_fee)
values(12,3,32,50000,"USD",50000); -- /32 (large ISP): $500/mo, $500 setup