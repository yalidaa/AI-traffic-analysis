import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


class DeploymentAssetTests(unittest.TestCase):
    def test_systemd_separates_privileged_capture_from_non_root_inference(self):
        capture = (DEPLOY / "systemd" / "mineshark-capture.service").read_text(encoding="utf-8")
        sensor = (DEPLOY / "systemd" / "mineshark-sensor.service").read_text(encoding="utf-8")

        self.assertIn("User=mineshark", capture)
        self.assertIn("mineshark-capture --config /etc/mineshark/sensor.toml", capture)
        self.assertNotIn("AmbientCapabilities", capture)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN", capture)
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('mineshark-capture = "mineshark.sensor.capture:capture_main"', pyproject)
        self.assertIn("User=mineshark", sensor)
        self.assertIn("NoNewPrivileges=true", sensor)
        self.assertNotIn("CAP_NET_RAW", sensor)
        self.assertIn("mineshark-sensor --config /etc/mineshark/sensor.toml run", sensor)

    def test_wazuh_agent_and_rules_cover_events_and_risk_levels(self):
        agent = (DEPLOY / "wazuh" / "ossec-mineshark.conf").read_text(encoding="utf-8")
        rules = (DEPLOY / "wazuh" / "mineshark_rules.xml").read_text(encoding="utf-8")

        self.assertIn("/var/log/mineshark/events.jsonl", agent)
        self.assertIn("json", agent)
        for event_type in ("ai_alert", "evidence_snapshot", "sensor_heartbeat"):
            self.assertIn(event_type, rules)
        for risk_level in ("low", "medium", "high"):
            self.assertIn(risk_level, rules)
        self.assertIn('<field name="schema_version">', rules)
        self.assertIn('<field name="event_type">', rules)
        self.assertIn('<field name="risk_level">', rules)
        self.assertNotIn('<field name="data.event_type">', rules)
        self.assertNotIn('<field name="data.risk_level">', rules)
        rule_nodes = {rule.attrib["id"]: rule for rule in ET.fromstring(rules).findall("rule")}
        for rule_id in ("110101", "110102", "110103"):
            parents = {sid.strip() for sid in (rule_nodes[rule_id].findtext("if_sid") or "").split(",")}
            self.assertEqual(parents, {"110100", "86600"})
        self.assertIn("110101", rules)

    def test_nginx_terminates_tls_and_does_not_enable_public_cors(self):
        nginx = (DEPLOY / "nginx" / "mineshark.conf").read_text(encoding="utf-8")
        self.assertIn("listen 443 ssl http2", nginx)
        self.assertIn("ssl_certificate", nginx)
        self.assertIn("auth_basic", nginx)
        self.assertIn("proxy_pass http://127.0.0.1:8000", nginx)
        self.assertNotIn("Access-Control-Allow-Origin *", nginx)

    def test_offline_builder_and_installer_are_non_destructive(self):
        builder = (ROOT / "scripts" / "deployment" / "build_offline_bundle.py").read_text(encoding="utf-8")
        installer = (DEPLOY / "install.sh").read_text(encoding="utf-8")

        for required in (
            "wheels",
            "model-manifest.json",
            "web/frontend/dist",
            "BUNDLE-MANIFEST.json",
            "SHA256SUMS",
        ):
            self.assertIn(required, builder)
        self.assertIn('sys.platform != "linux"', builder)
        self.assertIn("https://download.pytorch.org/whl/cpu", builder)
        self.assertIn('staging / "tools"', builder)
        self.assertIn('copy_tree(ROOT / "deploy" / "wsl-lab"', builder)
        for directory in (
            "/etc/mineshark",
            "/opt/mineshark/models",
            "/var/lib/mineshark",
            "/var/log/mineshark",
            "/var/spool/mineshark",
        ):
            self.assertIn(directory, installer)
        self.assertIn("refusing to overwrite unmanaged configuration", installer)
        self.assertIn("setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap", installer)
        self.assertIn("wireshark zeek suricata", installer)
        self.assertNotIn("rm -rf", installer)
        self.assertNotIn("find ", installer)

    def test_console_deployment_uses_writable_runtime_outputs(self):
        service = (DEPLOY / "systemd" / "mineshark-console.service").read_text(encoding="utf-8")
        env_example = (DEPLOY / "console.env.example").read_text(encoding="utf-8")
        installer = (DEPLOY / "install-console.sh").read_text(encoding="utf-8")

        self.assertIn("ReadWritePaths=/var/lib/mineshark /var/log/mineshark", service)
        for value in (
            "MINESHARK_OUTPUT_ROOT=/var/lib/mineshark/outputs",
            "MINESHARK_KNOWLEDGE_FILE=/var/lib/mineshark/security_playbook.jsonl",
            "MINESHARK_RAG_INDEX_DIR=/var/lib/mineshark/outputs/rag",
        ):
            self.assertIn(value, env_example)
        self.assertIn("configs/reporting/security_playbook.jsonl", installer)
        self.assertIn("/var/lib/mineshark/security_playbook.jsonl", installer)

    def test_wsl_deployment_builds_rag_after_installing_knowledge(self):
        for script_path in (DEPLOY / "wsl-lab" / "install-guest.sh", DEPLOY / "wsl-lab" / "repair-guest.sh"):
            script = script_path.read_text(encoding="utf-8")
            self.assertIn(
                'runuser -u mineshark -- /opt/mineshark/venv/bin/mineshark-build-rag --env-file "${console_env}"',
                script,
            )
            self.assertLess(
                script.index("security_playbook.jsonl"),
                script.index("mineshark-build-rag"),
            )

    def test_frontend_deployment_rejects_dark_build_and_starts_zeek(self):
        guest_installer = (DEPLOY / "wsl-lab" / "install-guest.sh").read_text(encoding="utf-8")
        zeek_service = (DEPLOY / "wsl-lab" / "mineshark-zeek.service").read_text(encoding="utf-8")
        styles = (ROOT / "web" / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("color-scheme: light", styles)
        self.assertIn("color-scheme:light", guest_installer)
        self.assertIn("mineshark-zeek.service", guest_installer)
        self.assertIn("/opt/zeek/bin/zeekctl deploy", zeek_service)
        self.assertIn("/opt/zeek/bin/zeekctl stop", zeek_service)

    def test_chinese_deployment_and_acceptance_runbooks_exist(self):
        deployment = (ROOT / "docs" / "real_sensor_deployment.md").read_text(encoding="utf-8")
        acceptance = (ROOT / "docs" / "real_sensor_acceptance.md").read_text(encoding="utf-8")
        for topic in ("SPAN/TAP", "升级", "备份恢复", "证书", "卸载"):
            self.assertIn(topic, deployment)
        for gate in ("p95", "100 Mbps", "0.1%", "60 秒", "五分钟"):
            self.assertIn(gate, acceptance)
        wsl_runbook = (ROOT / "docs" / "wsl_lab_deployment.md").read_text(encoding="utf-8")
        for topic in ("MineShark-Lab", "MineShark-WLANCapture", "普通 WLAN", "SPAN/TAP"):
            self.assertIn(topic, wsl_runbook)

    def test_wsl_lab_profile_uses_windows_capture_and_isolated_ubuntu(self):
        host_installer = (DEPLOY / "wsl-lab" / "install-host.ps1").read_text(encoding="utf-8")
        guest_installer = (DEPLOY / "wsl-lab" / "install-guest.sh").read_text(encoding="utf-8")
        sensor_service = (DEPLOY / "wsl-lab" / "mineshark-sensor-wsl.service").read_text(encoding="utf-8")
        sensor_config = (DEPLOY / "wsl-lab" / "sensor.toml").read_text(encoding="utf-8")

        for required in (
            'DistroName = "MineShark-Lab"',
            'DistroLocation = "E:\\WSL\\MineShark-Lab"',
            'SpoolDirectory = "E:\\MineShark-runtime\\spool"',
            '"tcp"',
            '"128"',
            '"duration:5"',
            '"files:60"',
        ):
            self.assertIn(required, host_installer)
        self.assertIn("Ubuntu-22.04", host_installer)
        self.assertIn("MineShark-WLANCapture", host_installer)
        self.assertIn("sleep infinity", host_installer)
        self.assertIn("--exec /bin/sleep infinity", host_installer)
        self.assertNotIn("/bin/bash -lc", host_installer)
        self.assertNotIn("--exec /bin/true", host_installer)
        self.assertIn("Get-ItemProperty", host_installer)
        self.assertIn("InstallLocation", host_installer)
        self.assertNotIn("Wazuh", host_installer)
        self.assertNotIn("Remove-Item", host_installer)

        self.assertIn('"${VERSION_ID}" != "22.04"', guest_installer)
        self.assertIn("wazuh-install.sh", guest_installer)
        self.assertIn("MINESHARK_AI_ALERT_SOURCE=wazuh", guest_installer)
        self.assertIn("MINESHARK_ALLOWED_SENSOR_IDS=singlehost-wlan", guest_installer)
        self.assertIn("chmod 0755 /etc/mineshark", guest_installer)
        self.assertIn("satisfy any", guest_installer)
        self.assertIn("allow 127.0.0.1", guest_installer)
        self.assertIn("</ossec_config>", guest_installer)
        self.assertIn("config.replace(closing_tag,", guest_installer)
        repair_guest = (DEPLOY / "wsl-lab" / "repair-guest.sh").read_text(encoding="utf-8")
        self.assertIn("tomli==2.0.1", repair_guest)
        self.assertIn("config = config.replace(fragment", repair_guest)
        self.assertIn("chown -R mineshark:mineshark /var/lib/mineshark /var/log/mineshark", repair_guest)
        self.assertIn("systemctl enable --now", repair_guest)
        self.assertNotIn("rm -rf", guest_installer)

        self.assertIn("User=mineshark", sensor_service)
        self.assertIn("/mnt/e/MineShark-runtime/spool", sensor_service)
        self.assertNotIn("mineshark-capture.service", sensor_service)
        self.assertNotIn("CAP_NET_RAW", sensor_service)

        self.assertIn('sensor_id = "singlehost-wlan"', sensor_config)
        self.assertIn('spool_dir = "/mnt/e/MineShark-runtime/spool"', sensor_config)
        self.assertIn("snaplen = 128", sensor_config)
        self.assertIn("rotate_seconds = 5", sensor_config)
        self.assertIn("ring_files = 60", sensor_config)

    def test_wsl_lab_installs_pinned_network_evidence_sources(self):
        guest_installer = (DEPLOY / "wsl-lab" / "install-guest.sh").read_text(encoding="utf-8")
        sensor_config = (DEPLOY / "wsl-lab" / "sensor.toml").read_text(encoding="utf-8")
        runbook = (ROOT / "docs" / "wsl_lab_deployment.md").read_text(encoding="utf-8")

        self.assertIn('ZEEK_SERIES="${ZEEK_SERIES:-8.0}"', guest_installer)
        self.assertIn('ZEEK_EXPECTED_VERSION="${ZEEK_EXPECTED_VERSION:-8.0.9}"', guest_installer)
        self.assertIn("download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04", guest_installer)
        self.assertIn('"zeek-${ZEEK_SERIES}"', guest_installer)
        self.assertIn("${zeek_binary} --version", guest_installer)
        self.assertIn("/var/lib/mineshark/zeek-logs", guest_installer)
        self.assertNotIn("install -d -o root -g zeek -m 2770 /opt/zeek/logs/current", guest_installer)
        self.assertIn('SURICATA_PACKAGE_VERSION="${SURICATA_PACKAGE_VERSION:-1:6.0.4-3}"', guest_installer)
        self.assertIn("suricata=${SURICATA_PACKAGE_VERSION}", guest_installer)
        self.assertIn("suricata --build-info", guest_installer)
        self.assertIn("suricata-update", guest_installer)
        self.assertIn("-o /etc/suricata/rules", guest_installer)
        self.assertIn("suricata -T -c /etc/suricata/suricata.yaml", guest_installer)
        self.assertIn("ZEEK_LOG_DIR=/var/lib/mineshark/zeek-logs/current", guest_installer)
        self.assertIn('ZEEK_LOG_ROOT="/var/lib/mineshark/zeek-logs"', guest_installer)
        self.assertIn('lines[index] = f"LogDir = {log_root}"', guest_installer)
        self.assertIn("SURICATA_EVE_PATH=/var/log/suricata/eve.json", guest_installer)
        self.assertIn('zeek_log_dir = "/var/lib/mineshark/zeek-logs/current"', sensor_config)
        self.assertIn('suricata_eve_path = "/var/log/suricata/eve.json"', sensor_config)
        self.assertIn("Zeek 8.0.9", runbook)
        self.assertIn("Suricata 6.0.4", runbook)

    def test_wsl_lab_waits_for_indexer_after_final_service_start(self):
        guest_installer = (DEPLOY / "wsl-lab" / "install-guest.sh").read_text(encoding="utf-8")

        final_service_start = guest_installer.rfind(
            "systemctl enable --now wazuh-indexer wazuh-manager filebeat wazuh-dashboard nginx mineshark-sensor mineshark-console"
        )
        final_service_restart = guest_installer.rfind(
            "systemctl restart wazuh-manager mineshark-sensor mineshark-console"
        )
        final_indexer_wait = guest_installer.rfind("wait_for_indexer")

        self.assertGreater(final_service_start, -1)
        self.assertGreater(final_service_restart, final_service_start)
        self.assertGreater(final_indexer_wait, final_service_restart)
        self.assertIn("systemctl is-active --quiet wazuh-indexer", guest_installer)
        self.assertIn(
            'curl --fail --silent --insecure --user "admin:${admin_password}" https://127.0.0.1:9200/',
            guest_installer,
        )


if __name__ == "__main__":
    unittest.main()
