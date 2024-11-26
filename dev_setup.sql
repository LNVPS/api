insert
ignore into vm_host_region(id,name,enabled) values(1,"uat",1);
insert
ignore into vm_host(id,kind,region_id,name,ip,cpu,memory,enabled,api_token)
values(1, 0, 1, "lab", "https://185.18.221.8:8006", 4, 4096*1024, 1, "root@pam!tester=c82f8a57-f876-4ca4-8610-c086d8d9d51c");
insert
ignore into vm_host_disk(id,host_id,name,size,kind,interface,enabled)
values(1,1,"local-lvm",1000*1000*1000*1000, 0, 0, 1);
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
ignore into ip_range(id,cidr,enabled,region_id)
values(1,"185.18.221.80/28",1,1);
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