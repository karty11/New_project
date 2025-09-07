output "iam_role_arn" {
  value = aws_iam_role.external_secrets_role.arn
}

output "oidc_provider" {
  value = aws_iam_openid_connect_provider.eks.url
}
