output "public_bucket_name" {
  value = aws_s3_bucket.public_data.id
}

output "open_security_group_id" {
  value = aws_security_group.wide_open.id
}

output "unencrypted_volume_id" {
  value = aws_ebs_volume.unencrypted.id
}

output "wildcard_policy_arn" {
  value = aws_iam_policy.overly_permissive.arn
}
