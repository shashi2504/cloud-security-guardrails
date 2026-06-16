package security

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────────────
# POLICY: SSH must never be open to 0.0.0.0/0 or ::/0
# Applies to both aws_security_group and
# aws_security_group_rule resources
# ─────────────────────────────────────────────────────

# Block open SSH on aws_security_group inline rules
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"

  ingress := resource.change.after.ingress[_]
  ingress.from_port <= 22
  ingress.to_port >= 22
  ingress.protocol == "tcp"

  cidr := ingress.cidr_blocks[_]
  _is_open_cidr(cidr)

  msg := sprintf(
    "POLICY VIOLATION: Security group '%s' allows SSH from %s. SSH must be restricted to specific IPs.",
    [resource.address, cidr]
  )
}

# Block open SSH on aws_security_group_rule resources
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.after.type == "ingress"

  resource.change.after.from_port <= 22
  resource.change.after.to_port >= 22
  resource.change.after.protocol == "tcp"

  cidr := resource.change.after.cidr_blocks[_]
  _is_open_cidr(cidr)

  msg := sprintf(
    "POLICY VIOLATION: Security group rule '%s' allows SSH from %s.",
    [resource.address, cidr]
  )
}

# Block any port open to 0.0.0.0/0 via UDP too
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"

  ingress := resource.change.after.ingress[_]
  ingress.from_port == 0
  ingress.to_port == 0
  ingress.protocol == "-1"    # All traffic

  cidr := ingress.cidr_blocks[_]
  _is_open_cidr(cidr)

  msg := sprintf(
    "POLICY VIOLATION: Security group '%s' allows ALL traffic from %s. Never allow protocol=-1 from open CIDRs.",
    [resource.address, cidr]
  )
}

# Helper — matches both IPv4 and IPv6 open CIDRs
_is_open_cidr(cidr) if cidr == "0.0.0.0/0"
_is_open_cidr(cidr) if cidr == "::/0"
