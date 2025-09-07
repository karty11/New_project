data "aws_eks_cluster" "cluster" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = var.cluster_name
}

data "aws_caller_identity" "current" {}

locals {
  oidc_provider_url = replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")
  oidc_sub_key      = "${local.oidc_provider_url}:sub"
}

data "tls_certificate" "oidc" {
  url = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.sha1_fingerprint]
}
# }
# resource "aws_iam_openid_connect_provider" "eks" {
#   url             = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
#   client_id_list  = ["sts.amazonaws.com"]
#   thumbprint_list = [data.external.oidc_thumbprint.result.["thumbprint"]]
# }

data "aws_iam_policy_document" "irsa_assume_role" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = local.oidc_sub_key
      values   = ["system:serviceaccount:${var.eks_sa_namespace}:${var.eks_sa_name}"]
    }
  }
}

resource "aws_iam_role" "external_secrets_irsa" {
  name               = "external-secrets-irsa"
  assume_role_policy = data.aws_iam_policy_document.irsa_assume_role.json
  tags = {
    "Name" = "external-secrets-irsa"
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


resource "aws_iam_role_policy" "external_secrets_access" {
  name   = "external-secrets-access"
  role   = aws_iam_role.external_secrets_irsa.id
  policy = data.aws_iam_policy_document.irsa_assume_role.json
}