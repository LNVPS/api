-- Add ON DELETE CASCADE to pure owned-child tables.
--
-- These tables hold rows that are meaningless without their parent and carry no
-- financial/audit value or external side effects. Enforcing the cascade at the
-- DB level lets us drop hand-written multi-statement cleanup in the delete_*
-- methods and fixes several latent bugs where deleting a parent that still had
-- children failed with a FK violation (admin_delete_router with cached
-- tunnel/BGP inventory; delete_referral with existing payouts).
--
-- Financial/audit/soft-deleted tables (vm, subscription, subscription_payment,
-- vm_history, vm_ip_assignment, vm_firewall_rule) are deliberately left with
-- RESTRICT and continue to be cleaned up explicitly.

-- users -> owned children
alter table user_ssh_key
    drop foreign key fk_ssh_key_user,
    add constraint fk_ssh_key_user foreign key (user_id) references users (id) on delete cascade;

alter table user_webauthn_credentials
    drop foreign key fk_webauthn_cred_user,
    add constraint fk_webauthn_cred_user foreign key (user_id) references users (id) on delete cascade;

alter table user_payment_method
    drop foreign key fk_user_payment_method_user,
    add constraint fk_user_payment_method_user foreign key (user_id) references users (id) on delete cascade;

-- referral chain: users -> referral -> referral_payout
-- These FKs were created without an explicit name, so MariaDB/InnoDB assigned
-- the deterministic <table>_ibfk_1 name (each table has exactly one FK).
alter table referral
    drop foreign key referral_ibfk_1,
    add constraint fk_referral_user foreign key (user_id) references users (id) on delete cascade;

alter table referral_payout
    drop foreign key referral_payout_ibfk_1,
    add constraint fk_referral_payout_referral foreign key (referral_id) references referral (id) on delete cascade;

-- router -> cached tunnel/BGP inventory (discovery caches, safe to drop)
alter table router_tunnel
    drop foreign key fk_router_tunnel_router,
    add constraint fk_router_tunnel_router foreign key (router_id) references router (id) on delete cascade;

alter table router_tunnel_traffic
    drop foreign key fk_router_tunnel_traffic_router,
    add constraint fk_router_tunnel_traffic_router foreign key (router_id) references router (id) on delete cascade;

alter table router_bgp_session
    drop foreign key fk_router_bgp_session_router,
    add constraint fk_router_bgp_session_router foreign key (router_id) references router (id) on delete cascade;

alter table router_bgp_route
    drop foreign key fk_router_bgp_route_router,
    add constraint fk_router_bgp_route_router foreign key (router_id) references router (id) on delete cascade;

-- vm_custom_pricing -> pricing disks (pure child; vm_custom_template keeps RESTRICT)
alter table vm_custom_pricing_disk
    drop foreign key fk_custom_pricing_disk,
    add constraint fk_custom_pricing_disk foreign key (pricing_id) references vm_custom_pricing (id) on delete cascade;
