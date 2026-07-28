# OpenBao PRODUCTION config (not dev mode). File storage backend, persistent.
# Must be initialized + unsealed once (bootstrap.sh / README). Reachable only
# on the internal compose network, so TLS is terminated at the network edge;
# tighten to in-cluster TLS if your threat model requires it.
storage "file" {
  path = "/openbao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://openbao:8200"
disable_mlock = false
ui            = false
