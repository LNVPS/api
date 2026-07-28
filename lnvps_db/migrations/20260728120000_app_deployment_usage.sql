-- Last observed resource usage of a deployment's workload, so a customer can
-- see consumption against the footprint they are paying for.
--
-- Written only by the operator, from Prometheus, on the reconcile pass that
-- also writes status. Kept on the deployment row rather than a history table:
-- the question being answered is "am I outgrowing this size", which a current
-- reading plus the quota already answers, and a per-minute time series for
-- every deployment is a different (and much more expensive) feature.
--
-- NULL means nothing has been observed yet — a deployment that has never run,
-- or a cluster with no metrics source. That is distinct from an observed zero,
-- so it is not defaulted.
--
-- Storage is nullable on its own terms: volume usage comes from the kubelet's
-- PVC statistics, which a deployment without volumes never reports.
ALTER TABLE app_deployment
    ADD COLUMN usage_cpu_milli     INTEGER UNSIGNED NULL DEFAULT NULL AFTER status_message,
    ADD COLUMN usage_memory_bytes  BIGINT UNSIGNED  NULL DEFAULT NULL AFTER usage_cpu_milli,
    ADD COLUMN usage_storage_bytes BIGINT UNSIGNED  NULL DEFAULT NULL AFTER usage_memory_bytes,
    ADD COLUMN usage_collected     TIMESTAMP        NULL DEFAULT NULL AFTER usage_storage_bytes;
