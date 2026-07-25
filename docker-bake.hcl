// Bake definition for the 5 main service images. All targets share one
// Dockerfile whose builder stage compiles the whole workspace once; each
// target just picks a different runtime stage. `docker buildx bake` builds
// them in a single graph so the expensive Rust build runs exactly once.

variable "REGISTRY" {
  default = "registry.v0l.io"
}

variable "TAG" {
  default = "latest"
}

variable "HOST_INFO_IMAGE" {
  default = "registry.v0l.io/lnvps-host-info:latest"
}

variable "REGISTRY_USER" {
  default = ""
}

variable "REGISTRY_PASS" {
  default = ""
}

group "default" {
  targets = ["lnvps-api", "lnvps-api-admin", "lnvps-operator", "lnvps-nostr", "lnvps-agent"]
}

target "_common" {
  context    = "."
  dockerfile = "Dockerfile"
  args = {
    HOST_INFO_IMAGE = HOST_INFO_IMAGE
    REGISTRY_USER   = REGISTRY_USER
    REGISTRY_PASS   = REGISTRY_PASS
  }
}

target "lnvps-api" {
  inherits = ["_common"]
  target   = "lnvps-api"
  tags     = ["${REGISTRY}/lnvps-api:${TAG}"]
}

target "lnvps-api-admin" {
  inherits = ["_common"]
  target   = "lnvps-api-admin"
  tags     = ["${REGISTRY}/lnvps-api-admin:${TAG}"]
}

target "lnvps-operator" {
  inherits = ["_common"]
  target   = "lnvps-operator"
  tags     = ["${REGISTRY}/lnvps-operator:${TAG}"]
}

target "lnvps-nostr" {
  inherits = ["_common"]
  target   = "lnvps-nostr"
  tags     = ["${REGISTRY}/lnvps-nostr:${TAG}"]
}

target "lnvps-agent" {
  inherits = ["_common"]
  target   = "lnvps-agent"
  tags     = ["${REGISTRY}/lnvps-agent:${TAG}"]
}
