ui = true

storage "raft" {
  path    = "/bao/data"
  node_id = "local-node"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"