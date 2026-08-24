-- Per-day VM traffic accounting and monthly outbound transfer quotas.
--
-- Traffic is sampled from the hypervisor's cumulative per-VM NIC counters on
-- the worker's existing VM sweep, so what is stored here is a running sum of
-- deltas between passes rather than anything the hypervisor reports directly.

-- One row per VM per UTC day, accumulated in place by the worker.
--
-- Bytes, not GB: the quota is expressed in GB but the samples are bytes, and
-- rounding each sample to GB would lose almost all of them.
create table vm_traffic_daily
(
    vm_id     integer unsigned not null,
    -- UTC date the traffic was attributed to
    day       date             not null,
    bytes_in  bigint unsigned  not null default 0,
    bytes_out bigint unsigned  not null default 0,
    updated   timestamp        not null default current_timestamp on update current_timestamp,
    primary key (vm_id, day),
    -- ON DELETE CASCADE, unlike the other vm_* children (see
    -- 20260720130000_cascade_delete_child_tables.sql). `delete_vm` is a soft
    -- delete that does not touch these rows, so ordinary VM lifecycle keeps the
    -- history; `hard_delete_vm` and the user purge are genuine purges, where
    -- removing it is the intent. Spelling that out as hand-written deletes in
    -- every purge path is how a new path silently fails the FK instead.
    constraint fk_vm_traffic_daily_vm foreign key (vm_id) references vm (id) on delete cascade
);

-- Index for "usage across all VMs in a period" reports, which the primary key
-- (vm_id first) cannot serve.
create index ix_vm_traffic_daily_day on vm_traffic_daily (day);

-- The previous raw counter reading per VM, which is what a delta is measured
-- against. Held in the database rather than the VM state cache because that
-- cache is a Redis key with a TTL: losing it would either drop traffic or, if
-- treated as a first sample, double-count a whole counter's worth.
--
-- Deliberately a separate table from vm_traffic_daily: this is transient state
-- overwritten every pass, while the daily rows are history retained for as long
-- as the VM exists.
create table vm_traffic_sample
(
    vm_id          integer unsigned not null primary key,
    last_bytes_in  bigint unsigned  not null default 0,
    last_bytes_out bigint unsigned  not null default 0,
    -- When the reading above was taken; a stale sample (VM off the sweep for a
    -- long time) is still a valid baseline, but it is useful to see.
    sampled        timestamp        not null default current_timestamp,
    constraint fk_vm_traffic_sample_vm foreign key (vm_id) references vm (id) on delete cascade
);

-- Monthly outbound transfer quota in GB. NULL = unmetered, which is what every
-- existing offer is, so no VM changes behaviour when this ships.
--
-- Outbound only, and quotas are informational in this pass: nothing throttles
-- or suspends on exceeding one, it only drives usage display and a warning
-- email.
alter table vm_template
    add column transfer_gb integer unsigned null default null;
alter table vm_custom_template
    add column transfer_gb integer unsigned null default null;
alter table vm_custom_pricing
    add column transfer_gb integer unsigned null default null;
