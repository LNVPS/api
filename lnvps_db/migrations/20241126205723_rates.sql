alter table vm_payment
    add column rate float;
update vm_payment set rate = 92000;
alter table vm_payment
    modify column rate float not null;