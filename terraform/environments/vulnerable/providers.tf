provider "aws" {
  region = "ap-south-1"

  default_tags {
    tags = {
      Project       = "cloud-security-guardrails"
      Environment   = "vulnerable"
      ManagedBy     = "terraform"
      AutoRemediate = "enabled"
      Warning       = "intentionally-insecure-do-not-use"
    }
  }
}
