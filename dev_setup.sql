insert ignore into vm_host(id,kind,name,ip,cpu,memory,enabled,api_token) values(1, 0, "lab", "https://185.18.221.8:8006", 4, 4096*1024, 1, "root@pam!tester=c82f8a57-f876-4ca4-8610-c086d8d9d51c");
insert ignore into vm_host_disk(id,host_id,name,size,kind,interface,enabled) values(1,1,"local-lvm",1000*1000*1000*1000, 0, 0, 1);
insert ignore into vm_os_image(id,name,enabled) values(1,"Ubuntu 24.04",1);
insert ignore into ip_range(id,cidr,enabled) values(1,"185.18.221.80/28",1);
insert ignore into vm_template(id,name,enabled,cpu,memory,disk_size,disk_id) values(1,"Basic",1,2,2048,1000*1000*1000*80,1);