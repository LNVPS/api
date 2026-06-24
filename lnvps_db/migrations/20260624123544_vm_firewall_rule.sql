-- Basic per-VM firewall rules (#36)
-- User-configurable ACCEPT/DROP rules applied on top of the always-enforced
-- ipfilter (anti-spoof) rules. Default policy remains allow-all (no regression).

create table vm_firewall_rule
(
    id             integer unsigned not null auto_increment primary key,
    vm_id          integer unsigned not null,
    -- Evaluation order; lower priority evaluated first
    priority       smallint unsigned not null default 0,
    -- 0 = inbound, 1 = outbound
    direction      smallint unsigned not null default 0,
    -- 0 = any, 1 = tcp, 2 = udp, 3 = icmp
    protocol       smallint unsigned not null default 0,
    -- 0 = drop, 1 = accept
    action         smallint unsigned not null default 1,
    -- Optional source CIDR (e.g. 1.2.3.0/24 or ::/0); NULL = any
    src_cidr       varchar(64)      null     default null,
    -- Optional destination port range (inclusive); NULL = any
    dst_port_start integer unsigned null     default null,
    dst_port_end   integer unsigned null     default null,
    -- Whether this rule is active
    enabled        bit(1)           not null default 1,
    created        timestamp        not null default current_timestamp,
    updated        timestamp        not null default current_timestamp on update current_timestamp,
    constraint fk_vm_firewall_rule_vm foreign key (vm_id) references vm (id)
);

create index ix_vm_firewall_rule_vm on vm_firewall_rule (vm_id);

-- Per-template max firewall rule count (NULL = use global default)
alter table vm_template        add column firewall_rule_limit smallint unsigned null default null;
alter table vm_custom_template add column firewall_rule_limit smallint unsigned null default null;
