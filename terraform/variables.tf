variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "cluster_name" {
  type = string
  default = "project-cluster"
}

variable "eks_sa_namespace" {
  type    = string
  default = "external-secrets"
}

variable "eks_sa_name" {
  type    = string
  default = "external-secrets-sa"
}


variable "oidc_thumbprint" {
  type    = string
  default = ""
}
