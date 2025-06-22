import os
from log_parser import parse_fgdump, parse_sysmon, parse_powershell, parse_log_file, get_target_label


def test_get_target_label():
    assert get_target_label('/path/to/attack_techniques/file.log') == 1
    assert get_target_label('/var/malware/sample.log') == 1
    assert get_target_label('/logs/honeypots/sample.log') == 0
    assert get_target_label('/logs/suspicious_behaviour/sample.log') == 1
    assert get_target_label('/logs/other/sample.log') == 0


def test_parse_fgdump():
    content = 'running fgdump.exe\nToken Elevation Type: %%1234'
    result = parse_fgdump(content)
    assert result['feat1'] == 1
    assert result['feat2'] == 1234


def test_parse_sysmon():
    content = '<EventID>5</EventID> mimikatz.exe'
    result = parse_sysmon(content)
    assert result['feat3'] == 5
    assert result['feat1'] == 1


def test_parse_powershell():
    content = 'ScriptBlockText=alpha\nScriptBlockText=beta gamma'
    result = parse_powershell(content)
    assert result['feat4'] == len('beta gamma')


def test_parse_log_file(tmp_path):
    log_path = tmp_path / 'sample_fgdump.log'
    log_content = 'fgdump.exe\nToken Elevation Type: %%99'
    log_path.write_text(log_content)
    result = parse_log_file(str(log_path))
    assert result['feat1'] == 1
    assert result['feat2'] == 99
    assert result['log_path'] == str(log_path)
    assert result['target'] == 0
