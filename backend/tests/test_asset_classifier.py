"""Tests for services.asset_classifier device-type classification.

Covers the expanded CPE/OS/OUI mappings introduced to recognise IoT cameras,
IP phones, access-control hardware, IoT/building-automation sensors, and the
broader printer/network-gear vendor catalogue.
"""
from types import SimpleNamespace

import pytest

from services.asset_classifier import (
    _OUI_DEVICE_MAP,
    _normalize_mac,
    classify_device_type,
    classify_device_type_from_mac,
    enrich_asset_from_os_plugins,
)


# ─────────────────────────────────────────────
# CPE-based classification
# ─────────────────────────────────────────────

class TestCpeFirewallRouterSwitch:
    """Pre-existing network-gear coverage should still work."""

    def test_palo_alto(self):
        assert classify_device_type(["cpe:/o:paloaltonetworks:pan-os:10.2"]) == "firewall"

    def test_cisco_asa(self):
        assert classify_device_type(["cpe:/o:cisco:adaptive_security_appliance:9.16"]) == "firewall"

    def test_cisco_ios(self):
        assert classify_device_type(["cpe:/o:cisco:ios:15.1"]) == "router"

    def test_cisco_nxos_is_switch(self):
        assert classify_device_type(["cpe:/o:cisco:nx-os:9.3"]) == "switch"

    def test_arista_eos(self):
        assert classify_device_type(["cpe:/o:arista:eos:4.27"]) == "switch"

    def test_juniper_srx_is_firewall(self):
        assert classify_device_type(["cpe:/o:juniper:srx:21.2"]) == "firewall"

    def test_meraki_mx_is_firewall(self):
        assert classify_device_type(["cpe:/h:cisco:meraki_mx100"]) == "firewall"

    def test_meraki_mr_is_wap(self):
        assert classify_device_type(["cpe:/h:cisco:meraki_mr46"]) == "wap"

    def test_meraki_ms_is_switch(self):
        assert classify_device_type(["cpe:/h:cisco:meraki_ms250"]) == "switch"

    def test_fortiswitch(self):
        assert classify_device_type(["cpe:/h:fortinet:fortiswitch_124f"]) == "switch"

    def test_fortiap(self):
        assert classify_device_type(["cpe:/h:fortinet:fortiap_231f"]) == "wap"

    def test_aruba_cx_switch(self):
        assert classify_device_type(["cpe:/o:hpe:aruba_cx_os:10.10"]) == "switch"


class TestCpeIpCameras:
    @pytest.mark.parametrize("cpe,expected", [
        ("cpe:/h:axis:p1448-le", "ip_camera"),
        ("cpe:/h:axis:m3068-p_network_camera", "ip_camera"),
        ("cpe:/h:hikvision:ds-2cd2143g0", "ip_camera"),
        ("cpe:/h:dahua:ipc-hdw5442", "ip_camera"),
        ("cpe:/h:hanwha:wisenet_xnv-6080", "ip_camera"),
        ("cpe:/h:bosch:flexidome_ip_4000i", "ip_camera"),
        ("cpe:/h:vivotek:fd9389", "ip_camera"),
        ("cpe:/h:reolink:rlc-820a", "ip_camera"),
        ("cpe:/h:pelco:sarix_imp221", "ip_camera"),
        ("cpe:/h:mobotix:mx-m26b", "ip_camera"),
        ("cpe:/h:uniview:ipc2122lr3", "ip_camera"),
        ("cpe:/h:avigilon:h5a-dome", "ip_camera"),
        ("cpe:/h:ring:doorbell_pro_2", "ip_camera"),
        ("cpe:/h:wyze:cam_v3", "ip_camera"),
        ("cpe:/h:google:nest_cam_outdoor", "ip_camera"),
        ("cpe:/h:arlo:pro_4", "ip_camera"),
    ])
    def test_camera_cpes_classify(self, cpe, expected):
        assert classify_device_type([cpe]) == expected


class TestCpeIpPhones:
    @pytest.mark.parametrize("cpe,expected", [
        ("cpe:/h:polycom:vvx_450", "ip_phone"),
        ("cpe:/h:polycom:trio_8800", "ip_phone"),
        ("cpe:/h:poly:ccx_500", "ip_phone"),
        ("cpe:/h:yealink:t46s", "ip_phone"),
        ("cpe:/h:grandstream:gxp2170", "ip_phone"),
        ("cpe:/h:grandstream:grp2614", "ip_phone"),
        ("cpe:/h:snom:d735", "ip_phone"),
        ("cpe:/h:mitel:6920_sip_phone", "ip_phone"),
        ("cpe:/h:avaya:j179_sip_phone", "ip_phone"),
        ("cpe:/h:cisco:cp-8845", "ip_phone"),
        ("cpe:/h:cisco:7945_ip_phone", "ip_phone"),
        ("cpe:/h:fanvil:x7a", "ip_phone"),
        ("cpe:/h:unify:openstage_60", "ip_phone"),
    ])
    def test_phone_cpes_classify(self, cpe, expected):
        assert classify_device_type([cpe]) == expected

    def test_polycom_video_codec_stays_voip(self):
        """Polycom HDX is a room codec — voip infrastructure, not an endpoint phone."""
        assert classify_device_type(["cpe:/h:polycom:hdx_8000"]) == "voip"

    def test_cisco_unified_communications_stays_voip(self):
        assert classify_device_type(["cpe:/a:cisco:unified_communications_manager:14"]) == "voip"


class TestCpeAccessControl:
    @pytest.mark.parametrize("cpe,expected", [
        ("cpe:/h:hid_global:signo_20", "access_control"),
        ("cpe:/h:hid_global:iclass_se_r10", "access_control"),
        ("cpe:/h:lenels2:netbox_4300", "access_control"),
        ("cpe:/h:honeywell:prowatch_ipro", "access_control"),
        ("cpe:/h:suprema:biostation_2", "access_control"),
        ("cpe:/h:zkteco:k40", "access_control"),
        ("cpe:/h:axis:a1601_door_controller", "access_control"),
        ("cpe:/h:paxton:net2_plus", "access_control"),
    ])
    def test_access_control_cpes_classify(self, cpe, expected):
        assert classify_device_type([cpe]) == expected


class TestCpeIotSensors:
    @pytest.mark.parametrize("cpe,expected", [
        ("cpe:/h:shelly:plus_1pm", "iot_sensor"),
        ("cpe:/h:tp-link:kasa_kp115", "iot_sensor"),
        ("cpe:/h:tp-link:tapo_p100", "iot_sensor"),
        ("cpe:/h:tuya:wb3s", "iot_sensor"),
        ("cpe:/h:ecobee:smartthermostat", "iot_sensor"),
        ("cpe:/h:sonos:beam_gen2", "iot_sensor"),
        ("cpe:/h:philips:hue_bridge", "iot_sensor"),
        ("cpe:/h:lutron:caseta_pro", "iot_sensor"),
        ("cpe:/h:crestron:cp4-r", "iot_sensor"),
        ("cpe:/h:raspberrypi:4_model_b", "iot_sensor"),
    ])
    def test_iot_cpes_classify(self, cpe, expected):
        assert classify_device_type([cpe]) == expected


class TestCpePrinters:
    @pytest.mark.parametrize("cpe,expected", [
        ("cpe:/h:hp:laserjet_pro_m404", "printer"),
        ("cpe:/h:hp:officejet_pro_9015", "printer"),
        ("cpe:/h:canon:imagerunner_c3525", "printer"),
        ("cpe:/h:canon:imageclass_mf445", "printer"),
        ("cpe:/h:xerox:workcentre_6515", "printer"),
        ("cpe:/h:xerox:versalink_c405", "printer"),
        ("cpe:/h:brother:mfc-l8900cdw_mfp", "printer"),
        ("cpe:/h:brother:hl-l3270cdw_laser", "printer"),
        ("cpe:/h:lexmark:mx521", "printer"),
        ("cpe:/h:ricoh:aficio_mp_c3504", "printer"),
        ("cpe:/h:kyocera:ecosys_m5526", "printer"),
        ("cpe:/h:sharp:mx-3071", "printer"),
        ("cpe:/h:konica_minolta:bizhub_c360i", "printer"),
        ("cpe:/h:oki:mc573dn", "printer"),
        ("cpe:/h:toshiba_tec:estudio_3508a", "printer"),
        ("cpe:/h:epson:workforce_pro_wf-c5790", "printer"),
        ("cpe:/h:samsung:proxpress_m4080", "printer"),
        ("cpe:/h:zebra:zt411_print_engine", "printer"),
    ])
    def test_printer_cpes_classify(self, cpe, expected):
        assert classify_device_type([cpe]) == expected


# ─────────────────────────────────────────────
# OS-string fallback
# ─────────────────────────────────────────────

class TestOsStringFallback:
    def test_axis_camera_os_string(self):
        assert classify_device_type([], "AXIS Network Camera firmware 10.12.0") == "ip_camera"

    def test_yealink_phone_os_string(self):
        assert classify_device_type([], "Yealink T48S SIP Phone") == "ip_phone"

    def test_polycom_vvx_phone_os_string(self):
        assert classify_device_type([], "Polycom VVX 411 UC Software 6.4.4") == "ip_phone"

    def test_generic_sip_phone_os_string(self):
        assert classify_device_type([], "Generic SIP Phone build 2023.1") == "ip_phone"

    def test_badge_reader_os_string(self):
        assert classify_device_type([], "HID iClass SE Card Reader") == "access_control"

    def test_door_controller_os_string(self):
        assert classify_device_type([], "Generic Door Controller v2") == "access_control"

    def test_smarthome_iot_os_string(self):
        assert classify_device_type([], "Sonos Play:5 firmware 80.1") == "iot_sensor"

    def test_bacnet_building_automation_os_string(self):
        assert classify_device_type([], "BACnet/IP HVAC controller") == "iot_sensor"

    def test_meraki_mr_os_string(self):
        assert classify_device_type([], "Cisco Meraki MR46 access point") == "wap"

    def test_fortigate_os_string(self):
        assert classify_device_type([], "FortiOS 7.2.4") == "firewall"

    def test_aruba_cx_os_string(self):
        assert classify_device_type([], "Aruba CX 6300 switch firmware") == "switch"

    def test_proxmox_hypervisor_os_string(self):
        assert classify_device_type([], "Proxmox VE 8.1") == "hypervisor"

    def test_windows_11_workstation_unchanged(self):
        assert classify_device_type([], "Windows 11 Pro 22H2") == "workstation"

    def test_windows_server_unchanged(self):
        assert classify_device_type([], "Windows Server 2022") == "server"

    def test_unknown_returns_none(self):
        assert classify_device_type([], "Some completely unrecognised firmware 1.0") is None


# ─────────────────────────────────────────────
# MAC OUI classification
# ─────────────────────────────────────────────

class TestMacNormalization:
    @pytest.mark.parametrize("raw,expected", [
        ("00:40:8C:11:22:33", "00408C112233"),
        ("00-40-8C-11-22-33", "00408C112233"),
        ("00408c112233",      "00408C112233"),
        ("0040.8c11.2233",    "00408C112233"),
        ("00:40:8C",          "00408C"),
    ])
    def test_normalize_strips_separators_uppercases(self, raw, expected):
        assert _normalize_mac(raw) == expected

    def test_empty_and_invalid_return_none(self):
        assert _normalize_mac("") is None
        assert _normalize_mac(None) is None
        assert _normalize_mac("xx:yy") is None  # too short after stripping non-hex


class TestOuiClassification:
    def test_axis_camera_oui(self):
        assert classify_device_type_from_mac("00:40:8C:AA:BB:CC") == "ip_camera"

    def test_hikvision_oui(self):
        assert classify_device_type_from_mac("44:A6:42:11:22:33") == "ip_camera"

    def test_dahua_oui(self):
        assert classify_device_type_from_mac("3C:0F:C1:55:66:77") == "ip_camera"

    def test_polycom_phone_oui(self):
        assert classify_device_type_from_mac("00:04:F2:DE:AD:BE") == "ip_phone"

    def test_yealink_phone_oui(self):
        assert classify_device_type_from_mac("80-5E-C0-12-34-56") == "ip_phone"

    def test_grandstream_phone_oui(self):
        assert classify_device_type_from_mac("000B82445566") == "ip_phone"

    def test_hid_access_control_oui(self):
        assert classify_device_type_from_mac("00:06:5B:01:02:03") == "access_control"

    def test_zkteco_access_control_oui(self):
        assert classify_device_type_from_mac("00:26:62:AA:BB:CC") == "access_control"

    def test_hp_printer_oui(self):
        assert classify_device_type_from_mac("00:01:E6:11:22:33") == "printer"

    def test_brother_printer_oui(self):
        assert classify_device_type_from_mac("00:1B:A9:CC:DD:EE") == "printer"

    def test_shelly_iot_oui(self):
        assert classify_device_type_from_mac("98:F4:AB:00:11:22") == "iot_sensor"

    def test_raspberry_pi_iot_oui(self):
        assert classify_device_type_from_mac("B8:27:EB:99:88:77") == "iot_sensor"

    def test_palo_alto_firewall_oui(self):
        assert classify_device_type_from_mac("00:1F:12:33:44:55") == "firewall"

    def test_juniper_router_oui(self):
        assert classify_device_type_from_mac("00:90:4B:AA:BB:CC") == "router"

    def test_ubiquiti_wap_oui(self):
        assert classify_device_type_from_mac("24:A4:3C:11:22:33") == "wap"

    def test_unknown_oui_returns_none(self):
        # IEEE block reserved as documentation / locally administered
        assert classify_device_type_from_mac("02:00:00:11:22:33") is None

    def test_garbage_input_returns_none(self):
        assert classify_device_type_from_mac("") is None
        assert classify_device_type_from_mac(None) is None
        assert classify_device_type_from_mac("not-a-mac") is None

    def test_all_oui_values_are_known_device_types(self):
        """Guard against typos: every value in the OUI map must be a recognised device_type."""
        allowed = {
            "server", "workstation", "router", "switch", "firewall", "printer",
            "hypervisor", "wap", "voip", "ip_camera", "ip_phone",
            "access_control", "iot_sensor", "storage",
        }
        for oui, dtype in _OUI_DEVICE_MAP.items():
            assert dtype in allowed, f"OUI {oui} maps to unknown device_type {dtype!r}"


# ─────────────────────────────────────────────
# Resolution order
# ─────────────────────────────────────────────

class TestResolutionOrder:
    def test_cpe_beats_os_string(self):
        # CPE says camera, OS string would say server (Linux) — CPE wins.
        assert classify_device_type(
            ["cpe:/h:axis:m3068-p_network_camera"],
            "Embedded Linux 4.14",
        ) == "ip_camera"

    def test_os_string_beats_mac_oui(self):
        # OS string says Yealink IP phone; MAC OUI is HP printer.
        # OS string takes precedence over OUI tiebreaker.
        assert classify_device_type(
            [],
            "Yealink T46S SIP Phone",
            mac="00:01:E6:11:22:33",
        ) == "ip_phone"

    def test_mac_used_only_when_cpe_and_os_silent(self):
        assert classify_device_type([], "", mac="00:40:8C:AA:BB:CC") == "ip_camera"

    def test_no_signal_returns_none(self):
        assert classify_device_type([], "", mac=None) is None
        assert classify_device_type([], "", mac="") is None


# ─────────────────────────────────────────────
# enrich_asset_from_os_plugins integration
# ─────────────────────────────────────────────

def _fake_asset(**overrides):
    """Mimic the Asset ORM attributes touched by enrich_asset_from_os_plugins."""
    defaults = dict(
        os=None,
        os_confidence=None,
        cpe=[],
        device_type=None,
        mac_address=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestEnrichAssetIntegration:
    def test_camera_via_cpe_plugin(self):
        asset = _fake_asset()
        enrich_asset_from_os_plugins(
            asset,
            plugin_11936_output="Remote operating system : AXIS Network Camera firmware 10.12.0\nConfidence Level : 95",
            plugin_45590_output="cpe:/h:axis:m3068-p_network_camera",
        )
        assert asset.device_type == "ip_camera"
        assert asset.os == "AXIS Network Camera firmware 10.12.0"
        assert asset.os_confidence == 95
        assert "cpe:/h:axis:m3068-p_network_camera" in asset.cpe

    def test_phone_via_os_string_only(self):
        asset = _fake_asset()
        enrich_asset_from_os_plugins(
            asset,
            plugin_11936_output="Remote operating system : Polycom VVX 411 UC Software 6.4.4\nConfidence Level : 80",
        )
        assert asset.device_type == "ip_phone"

    def test_mac_tiebreaker_when_no_cpe_no_os(self):
        asset = _fake_asset(mac_address="00:40:8C:DE:AD:BE")  # Axis OUI
        enrich_asset_from_os_plugins(asset)
        assert asset.device_type == "ip_camera"

    def test_does_not_overwrite_when_unknown(self):
        """If no signal matches, device_type stays as whatever it was."""
        asset = _fake_asset(device_type="server")
        enrich_asset_from_os_plugins(
            asset,
            plugin_11936_output="Remote operating system : Some custom appliance 1.0\nConfidence Level : 50",
        )
        # OS string doesn't match any rule, MAC absent → no overwrite
        assert asset.device_type == "server"
