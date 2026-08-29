import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from handler import open_admin_rules

PUBLIC = [{"CidrIp": "0.0.0.0/0"}]
INTERNAL = [{"CidrIp": "10.0.0.0/16"}]


def perm(from_port, to_port, ranges, proto="tcp"):
    return {
        "IpProtocol": proto,
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": ranges,
    }


def test_ssh_open_to_world_selected():
    assert len(open_admin_rules([perm(22, 22, PUBLIC)])) == 1


def test_rdp_open_to_world_selected():
    assert len(open_admin_rules([perm(3389, 3389, PUBLIC)])) == 1


def test_ssh_from_internal_cidr_not_selected():
    assert open_admin_rules([perm(22, 22, INTERNAL)]) == []


def test_https_open_to_world_not_selected():
    """443 open to the world is normal, not a finding."""
    assert open_admin_rules([perm(443, 443, PUBLIC)]) == []


def test_port_range_covering_ssh_selected():
    """A 0-65535 range exposes SSH even though FromPort is not 22."""
    assert len(open_admin_rules([perm(0, 65535, PUBLIC)])) == 1


def test_mixed_ranges_keeps_only_public():
    """A rule allowing both internal and public keeps only the public range."""
    result = open_admin_rules([perm(22, 22, PUBLIC + INTERNAL)])
    assert len(result) == 1
    assert result[0]["IpRanges"] == PUBLIC


def test_legitimate_rules_untouched():
    perms = [perm(443, 443, PUBLIC), perm(22, 22, INTERNAL), perm(22, 22, PUBLIC)]
    result = open_admin_rules(perms)
    assert len(result) == 1
    assert result[0]["FromPort"] == 22
    assert result[0]["IpRanges"] == PUBLIC


def test_rule_without_ports_ignored():
    """protocol -1 rules have no FromPort; do not crash."""
    assert open_admin_rules([{"IpProtocol": "-1", "IpRanges": PUBLIC}]) == []
