-- Optional customer-owned domain for an app deployment. The customer points a
-- CNAME at the deployment's assigned hostname; the operator adds the domain to
-- the Ingress and cert-manager issues a TLS cert (HTTP-01) once DNS resolves.
-- NULL = no custom domain (only the default `{name}.{ingress_domain}` host).
ALTER TABLE app_deployment
    ADD COLUMN custom_domain VARCHAR(255) NULL DEFAULT NULL AFTER hostname;
