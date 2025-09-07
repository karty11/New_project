terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}

# Data: read EKS cluster to get issuer
data "aws_eks_cluster" "cluster" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "eks_auth" {
  name = var.cluster_name
}

data "aws_caller_identity" "current" {}

locals {
  oidc_issuer = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  # extract only the domain portion (e.g. oidc.eks.us-west-2.amazonaws.com)
  oidc_domain = regex("^https://([^/]+)/.*", local.oidc_issuer)[0]
}

data "external" "oidc_thumbprint" {
  program = [
    "bash",
    "-c",
    <<-EOT
      set -euo pipefail
      domain="${local.oidc_domain}"
      cert_tmp="$(mktemp)"
      echo | openssl s_client -showcerts -connect "${domain}:443" 2>/dev/null \
        | openssl x509 -outform PEM > "${cert_tmp}"
      thumbprint=$(openssl x509 -in "${cert_tmp}" -fingerprint -noout -sha1 \
        | cut -d'=' -f2 | sed 's/://g' | tr '[:upper:]' '[:lower:]')
      rm -f "${cert_tmp}"
      jq -n --arg t "${thumbprint}" '{"thumbprint":$t}'
    EOT
  ]
}
resource "aws_iam_openid_connect_provider" "eks" {
  url             = local.oidc_issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.external.oidc_thumbprint.result.thumbprint]
}

data "aws_iam_policy_document" "irsa_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "${replace(local.oidc_issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.eks_sa_namespace}:${var.eks_sa_name}"]
    }
  }
}

resource "aws_iam_role" "external_secrets_role" {
  name               = "external-secrets-role-${var.cluster_name}"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume_role.json
  tags = {
    "eks-irsa" = "external-secrets"
  }
}

data "aws_iam_policy_document" "external_secrets_policy" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds",
      "secretsmanager:ListSecrets"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "external_secrets_role_policy" {
  name   = "ExternalSecretsAccessPolicy"
  role   = aws_iam_role.external_secrets_role.id
  policy = data.aws_iam_policy_document.external_secrets_policy.json
}


# # Create OIDC provider (only if you don't already have one)
# resource "aws_iam_openid_connect_provider" "eks" {
#   url = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
#   client_id_list = ["sts.amazonaws.com"]
#
#   # You should provide the thumbprint for the OIDC provider cert.
#   # Get it by: openssl s_client -showcerts -servername <oidc_host> -connect <oidc_host>:443 2>/dev/null | \
#   #    openssl x509 -fingerprint -noout -sha1 | sed -E 's/.*=//' | sed 's/://g'
#   thumbprint_list = [var.oidc_thumbprint]
# }
#
# # IAM role assume trust for the serviceAccount system:serviceaccount:<namespace>:<name>
# data "aws_iam_policy_document" "irsa_assume_role" {
#   statement {
#     effect = "Allow"
#
#     principals {
#       type        = "Federated"
#       identifiers = [aws_iam_openid_connect_provider.eks.arn]
#     }
#
#     actions = ["sts:AssumeRoleWithWebIdentity"]
#
#     condition {
#       test     = "StringEquals"
#       variable = "${local.oidc_issuer}:sub"
#       values   = ["system:serviceaccount:${var.eks_sa_namespace}:${var.eks_sa_name}"]
#     }
#   }
# }
#
# resource "aws_iam_role" "external_secrets_role" {
#   name               = "external-secrets-role-${var.cluster_name}"
#   assume_role_policy = data.aws_iam_policy_document.irsa_assume_role.json
#   tags = {
#     "eks-irsa" = "external-secrets"
#   }
# }
#
# # Inline policy granting read access to Secrets Manager and SSM (adjust Resource ARNs to tighten)
# data "aws_iam_policy_document" "external_secrets_policy" {
#   statement {
#     effect = "Allow"
#     actions = [
#       "secretsmanager:GetSecretValue",
#       "secretsmanager:DescribeSecret",
#       "secretsmanager:ListSecretVersionIds",
#       "secretsmanager:ListSecrets"
#     ]
#     resources = ["*"]
#   }
#
#   statement {
#     effect = "Allow"
#     actions = [
#       "ssm:GetParameter",
#       "ssm:GetParameters",
#       "ssm:GetParametersByPath"
#     ]
#     resources = ["*"]
#   }
# }
#
# resource "aws_iam_role_policy" "external_secrets_role_policy" {
#   name   = "ExternalSecretsAccessPolicy"
#   role   = aws_iam_role.external_secrets_role.id
#   policy = data.aws_iam_policy_document.external_secrets_policy.json
# }
