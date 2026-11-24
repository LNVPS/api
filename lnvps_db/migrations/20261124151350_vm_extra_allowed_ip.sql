create table vm_extra_allowed_ip
(
    id      integer unsigned not null auto_increment primary key,
    vm_id   integer unsigned not null,
    ip      varchar(64)      not null,
    comment varchar(200)     not null,
    created timestamp        not null default current_timestamp,
    constraint fk_vm_extra_allowed_ip_vm foreign key (vm_id) references vm (id)
);

create unique index ix_vm_extra_allowed_ip_vm_ip on vm_extra_allowed_ip (vm_id, ip);

insert into vm_extra_allowed_ip (vm_id, ip, comment)
select v.id, vip.ip, 'k8s ingress VIP'
from vm v
         cross join (select '185.18.221.135' as ip
                     union all
                     select '2a13:2c0::4dbc:733d:4d68:2e08') vip
where v.id in (2068, 2069, 2146)
  and v.deleted = 0
  and not exists (select 1
                  from vm_ip_assignment a
                           join vm o on o.id = a.vm_id
                  where a.ip = vip.ip
                    and a.deleted = 0
                    and o.user_id <> v.user_id);
