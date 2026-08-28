provider "aws" {
  region = "ap-south-1"

  default_tags {
    tags = {
      Project     = "cloud-security-guardrails"
      Environment = "dev"
      ManagedBy   = "terraform"
      AutoRemediate = "enabled"
    }
  }
}
