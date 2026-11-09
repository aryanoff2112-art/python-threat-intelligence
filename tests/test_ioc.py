import pandas as pd

from intelligence.ioc_matcher import IOCMatcher
from intelligence.otx_collector import parse_pulses
from intelligence.urlhaus_collector import parse_urlhaus_csv

URLHAUS = """# comment line
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-01-01 00:00:00","http://203.0.113.5/a.sh","online","2026-01-02","malware_download","elf","https://urlhaus.abuse.ch/url/1/","x"
"2","2026-01-01 00:00:00","http://Bad.Example./b.exe","online","2026-01-02","malware_download","exe","https://urlhaus.abuse.ch/url/2/","x"
"""


def _matcher():
    return IOCMatcher(pd.DataFrame(parse_urlhaus_csv(URLHAUS)), as_of="2026-01-15")


def test_urlhaus_parse_extracts_url_ip_domain():
    types = {(i["ioc_type"], i["value"]) for i in parse_urlhaus_csv(URLHAUS)}
    assert ("ip", "203.0.113.5") in types and ("domain", "bad.example") in types
    assert ("url", "http://203.0.113.5/a.sh") in types


def test_otx_parse_maps_types_and_skips_bad_ips():
    pulses = [{"name": "p", "indicators": [
        {"type": "IPv4", "indicator": "203.0.113.9"}, {"type": "IPv4", "indicator": "not-an-ip"},
        {"type": "hostname", "indicator": "EVIL.example"}, {"type": "FileHash-MD5", "indicator": "abc"}]}]
    got = {(i["ioc_type"], i["value"]) for i in parse_pulses(pulses)}
    assert got == {("ip", "203.0.113.9"), ("domain", "evil.example")}


def test_lookup_ip_domain_url_and_miss():
    m = _matcher()
    assert m.lookup("203.0.113.5") and m.lookup("BAD.example") and m.lookup("http://bad.example/x")
    assert m.lookup("198.51.100.1") is None


def test_match_flows_prefers_destination_and_aligns_index():
    m = _matcher()
    flows = pd.DataFrame({"src_ip": ["10.0.0.1", "10.0.0.2"], "dst_ip": ["203.0.113.5", "198.51.100.1"]},
                         index=[5, 9])
    out = m.match_flows(flows)
    assert list(out.index) == [5, 9] and out["ioc_match"].tolist() == [True, False]
    assert out.loc[5, "ioc_indicator"] == "203.0.113.5"
