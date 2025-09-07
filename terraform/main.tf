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

locals {
  oidc_issuer = replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")
}

# Create OIDC provider (only if you don't already have one)
resource "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]

  # You should provide the thumbprint for the OIDC provider cert.
  # Get it by: openssl s_client -showcerts -servername <oidc_host> -connect <oidc_host>:443 2>/dev/null | \
  #    openssl x509 -fingerprint -noout -sha1 | sed -E 's/.*=//' | sed 's/://g'
  thumbprint_list = [var.oidc_thumbprint]
}

# IAM role assume trust for the serviceAccount system:serviceaccount:<namespace>:<name>
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
      variable = "${local.oidc_issuer}:sub"
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

# Inline policy granting read access to Secrets Manager and SSM (adjust Resource ARNs to tighten)
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
