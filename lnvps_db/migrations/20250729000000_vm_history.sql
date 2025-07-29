-- VM History Log
-- Track all changes and operations performed on VMs
create table vm_history
(
    id                 integer unsigned not null auto_increment primary key,
    vm_id              integer unsigned not null,
    action_type        varchar(50)      not null, -- created, started, stopped, deleted, expired, renewed, reinstalled, etc.
    timestamp          timestamp default current_timestamp,
    initiated_by_user  integer unsigned null, -- null for system-initiated actions
    previous_state     json null, -- previous VM state/configuration if applicable
    new_state          json null, -- new VM state/configuration if applicable
    metadata           json null, -- additional context (error messages, payment info, etc.)
    description        text null, -- human-readable description of the change

    constraint fk_vm_history_vm foreign key (vm_id) references vm (id),
    constraint fk_vm_history_user foreign key (initiated_by_user) references users (id)
);

create index ix_vm_history_vm_id on vm_history (vm_id);
create index ix_vm_history_timestamp on vm_history (timestamp);
create index ix_vm_history_action_type on vm_history (action_type);