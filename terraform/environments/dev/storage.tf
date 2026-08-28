# Deliberately insecure — added to demonstrate the CI gate blocking a merge.
resource "aws_s3_bucket" "reports" {
  bucket = "csg-dev-reports-880636108185"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
