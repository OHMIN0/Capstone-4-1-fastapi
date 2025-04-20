# file_to_features.py

import os
import time
import pandas as pd
import datetime
import hashlib
import pefile
import lief
import yara
from signify.authenticode import SignedPEFile
from typing import Dict, Any, List, Tuple
from functools import lru_cache

# ====== 설정 (YARA 룰 경로) ======
YARA_RULES_DIR = "yara_rules"
CAPABILITIES_RULES_FILE = os.path.join(YARA_RULES_DIR, 'capabilities.yar')
PACKER_RULES_FILE = os.path.join(YARA_RULES_DIR, 'packer_compiler_signatures.yar')

# ====== YARA 룰 컴파일 함수 (캐싱 사용) ======
@lru_cache(maxsize=2)
def compile_yara_rules(filepath: str):
    """주어진 경로의 YARA 룰을 컴파일합니다. 실패 시 None 반환 및 경고 출력."""
    try:
        if not os.path.exists(filepath):
            print(f"[WARN] YARA rule file not found: {filepath}. Rule matching will be skipped.")
            return None
        compiled_rules = yara.compile(filepath=filepath)
        print(f"[INFO] YARA rule compiled successfully: {filepath}")
        return compiled_rules
    except Exception as e:
        print(f"[ERROR] Failed to compile YARA rule {filepath}: {e}")
        return None

# ====== Capabilities 정의 ======
# (사용자가 제공한 순서와 일치하는지 확인 - 순서 자체는 여기서 중요하지 않음)
all_capabilities = [
    'inject_thread', 'create_process', 'persistence', 'hijack_network', 'create_service', 'create_com_service',
    'network_udp_sock', 'network_tcp_listen', 'network_dyndns', 'network_toredo', 'network_smtp_dotNet',
    'network_smtp_raw', 'network_smtp_vb', 'network_p2p_win', 'network_tor', 'network_irc', 'network_http',
    'network_dropper', 'network_ftp', 'network_tcp_socket', 'network_dns', 'network_ssl', 'network_dga',
    'bitcoin', 'certificate', 'escalate_priv', 'screenshot', 'lookupip', 'dyndns', 'lookupgeo', 'keylogger',
    'cred_local', 'sniff_audio', 'cred_ff', 'cred_vnc', 'cred_ie7', 'sniff_lan', 'migrate_apc', 'spreading_file',
    'spreading_share', 'rat_vnc', 'rat_rdp', 'rat_telnet', 'rat_webcam', 'win_mutex', 'win_registry', 'win_token',
    'win_private_profile', 'win_files_operation', 'Str_Win32_Winsock2_Library', 'Str_Win32_Wininet_Library',
    'Str_Win32_Internet_API', 'Str_Win32_Http_API', 'ldpreload', 'mysql_database_presence'
]

# ====== 특징 추출 헬퍼 함수들 (클래스 외부로 분리) ======
# (이전과 동일 - 변경 없음)
def _get_characteristics_list(binary: lief.PE.Binary) -> List[str]:
    try:
        if (binary and hasattr(binary, 'optional_header') and
                isinstance(binary.optional_header, lief.PE.OptionalHeader) and
                hasattr(binary.optional_header, 'dll_characteristics') and
                isinstance(binary.optional_header.dll_characteristics, list)):
            return [str(x).split('.')[-1] for x in binary.optional_header.dll_characteristics]
        return []
    except Exception as e:
        print(f"[WARN] Failed to get characteristics list: {e}")
        return []

def _has_manifest(binary: lief.PE.Binary) -> int:
    try:
        return int(binary and binary.has_resources and hasattr(binary, 'resources_manager') and binary.resources_manager.has_manifest)
    except Exception as e:
        print(f"[WARN] Failed to check manifest: {e}")
        return -1

def _has_aslr(binary: lief.PE.Binary) -> int:
    return int("DYNAMIC_BASE" in _get_characteristics_list(binary))

def _has_tls(binary: lief.PE.Binary) -> int:
    try:
        return int(binary and binary.has_tls)
    except Exception as e:
        print(f"[WARN] Failed to check TLS: {e}")
        return -1

def _has_dep(binary: lief.PE.Binary) -> int:
    return int("NX_COMPAT" in _get_characteristics_list(binary))

def _check_ci(binary: lief.PE.Binary) -> int:
    try:
        if binary and binary.has_configuration:
            config = binary.load_configuration
            if isinstance(config, tuple(getattr(lief.PE, f'LoadConfigurationV{i}') for i in range(2, 12) if hasattr(lief.PE, f'LoadConfigurationV{i}'))) and hasattr(config, 'code_integrity'):
                return 1
            else:
                 return 0
        return -1
    except Exception as e:
        print(f"[WARN] Failed to check Code Integrity: {e}")
        return -1

def _supports_cfg(binary: lief.PE.Binary) -> int:
    return int("GUARD_CF" in _get_characteristics_list(binary))

def _suspicious_dbgts(binary: lief.PE.Binary) -> int:
    try:
        if binary and binary.has_debug:
            for item in binary.debug:
                if hasattr(item, 'timestamp') and isinstance(item.timestamp, int) and item.timestamp > 0:
                    ts = item.timestamp
                    dbg_time = datetime.datetime.fromtimestamp(ts)
                    if dbg_time > datetime.datetime.now():
                        return 1
            return 0
        return -1
    except OverflowError:
        print(f"[WARN] Debug timestamp value out of range.")
        return -1
    except Exception as e:
        print(f"[WARN] Failed to check debug timestamp: {e}")
        return -1

def _is_signed(filename: str) -> int:
    try:
        with open(filename, "rb") as f:
            signed_pe = SignedPEFile(f)
            if signed_pe.signed:
                 return 1
            else:
                 return 0
    except Exception as e:
        print(f"[WARN] Failed to check signature for {os.path.basename(filename)}: {e}")
        return -1

def _is_packed(filename: str) -> int:
    packer_rules = compile_yara_rules(PACKER_RULES_FILE)
    if packer_rules is None:
        print("[WARN] Packer YARA rules not compiled/loaded. Skipping packing check.")
        return -1
    try:
        matches = packer_rules.match(filename)
        return int(any(m.tags and 'packer' in m.tags for m in matches))
    except yara.Error as e:
        print(f"[WARN] YARA matching error (packer) for {os.path.basename(filename)}: {e}")
        return -1
    except Exception as e:
        print(f"[WARN] Failed to check packing for {os.path.basename(filename)}: {e}")
        return -1

def _calculate_sha256(filename: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to calculate SHA256 for {os.path.basename(filename)}: {e}")
        return "error_calculating_hash"

# ====== PEFile 분석 클래스 (수정됨) ======
class PEFileAn:
    def __init__(self, filename: str):
        self.filename = filename
        self.features: Dict[str, Any] = {'filename': os.path.basename(filename)}

        binary: lief.PE.Binary | None = None
        pe: pefile.PE | None = None

        try:
            binary = lief.parse(filename)
            if binary is None: raise ValueError("Lief parse failed.")
        except Exception as e: raise ValueError(f"Lief parse error: {e}")

        try:
            pe = pefile.PE(filename, fast_load=False)
        except Exception as e: raise ValueError(f"Pefile load error: {e}")

        self.features['sha256'] = _calculate_sha256(filename)

        # PE header features
        if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
            opt_header = pe.OPTIONAL_HEADER
            self.features['MajorLinkerVersion'] = getattr(opt_header, 'MajorLinkerVersion', 0)
            self.features['MinorLinkerVersion'] = getattr(opt_header, 'MinorLinkerVersion', 0)
            self.features['SizeOfUninitializedData'] = getattr(opt_header, 'SizeOfUninitializedData', 0)
            self.features['ImageBase'] = getattr(opt_header, 'ImageBase', 0)
            self.features['FileAlignment'] = getattr(opt_header, 'FileAlignment', 0)
            self.features['MajorOperatingSystemVersion'] = getattr(opt_header, 'MajorOperatingSystemVersion', 0)
            self.features['MajorImageVersion'] = getattr(opt_header, 'MajorImageVersion', 0)
            self.features['MinorImageVersion'] = getattr(opt_header, 'MinorImageVersion', 0)
            self.features['MajorSubsystemVersion'] = getattr(opt_header, 'MajorSubsystemVersion', 0)
            self.features['SizeOfImage'] = getattr(opt_header, 'SizeOfImage', 0)
            self.features['SizeOfHeaders'] = getattr(opt_header, 'SizeOfHeaders', 0)
            self.features['CheckSum'] = getattr(opt_header, 'CheckSum', 0)
            self.features['Subsystem'] = getattr(opt_header, 'Subsystem', 0)
            self.features['DllCharacteristics'] = getattr(opt_header, 'DllCharacteristics', 0)
            self.features['SizeOfStackReserve'] = getattr(opt_header, 'SizeOfStackReserve', 0)
            self.features['SizeOfHeapReserve'] = getattr(opt_header, 'SizeOfHeapReserve', 0)
            self.features['BaseOfData'] = getattr(opt_header, 'BaseOfData', 0)
        else:
            print(f"[WARN] Optional Header not found or invalid in {self.features['filename']}")
            optional_header_fields = ['MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfUninitializedData', 'ImageBase', 'FileAlignment', 'MajorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfHeapReserve', 'BaseOfData']
            for field in optional_header_fields: self.features[field] = 0

        if hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
            file_header = pe.FILE_HEADER
            self.features['NumberOfSections'] = getattr(file_header, 'NumberOfSections', 0)
            self.features['Characteristics'] = getattr(file_header, 'Characteristics', 0)
        else:
            print(f"[WARN] File Header not found or invalid in {self.features['filename']}")
            self.features['NumberOfSections'] = 0
            self.features['Characteristics'] = 0

        if hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER:
            dos_header = pe.DOS_HEADER
            self.features['e_cblp'] = getattr(dos_header, 'e_cblp', 0)
            self.features['e_lfanew'] = getattr(dos_header, 'e_lfanew', 0)
        else:
             print(f"[WARN] DOS Header not found or invalid in {self.features['filename']}")
             self.features['e_cblp'] = 0
             self.features['e_lfanew'] = 0

        try:
            if hasattr(pe, 'sections') and isinstance(pe.sections, list) and pe.sections:
                self.features['SizeOfRawData'] = sum(getattr(s, 'SizeOfRawData', 0) for s in pe.sections)
                self.features['Misc'] = sum(getattr(s, 'Misc_VirtualSize', 0) for s in pe.sections)
            else:
                self.features['SizeOfRawData'] = 0
                self.features['Misc'] = 0
        except Exception as e:
            print(f"[WARN] Error calculating section features for {self.features['filename']}: {e}")
            self.features['SizeOfRawData'] = 0
            self.features['Misc'] = 0

        # 추가 분석 플래그 (lief 사용)
        if binary:
            self.features['has_manifest'] = _has_manifest(binary)
            self.features['has_aslr'] = _has_aslr(binary)
            self.features['has_tls'] = _has_tls(binary)
            self.features['has_dep'] = _has_dep(binary)
            self.features['code_integrity'] = _check_ci(binary)
            self.features['supports_cfg'] = _supports_cfg(binary)
            self.features['suspicious_dbgts'] = _suspicious_dbgts(binary)
        else:
            lief_flags = ['has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg', 'suspicious_dbgts']
            for flag in lief_flags: self.features[flag] = -1

        if pe and hasattr(pe, 'close'):
            try: pe.close()
            except Exception as close_e: print(f"[WARN] Error closing pefile object: {close_e}")

    def build(self) -> Dict[str, Any]:
        return self.features

# ====== 메인 특징 추출 및 저장 함수 ======
def extract_features_for_file(input_file_path: str) -> Tuple[Dict[str, Any], str | None]:
    """
    주어진 단일 PE 파일 경로로부터 특징을 추출하고, 결과를 딕셔너리로 반환하며,
    동일 디렉토리에 CSV 파일로 저장합니다. (지정된 열 순서 적용)
    """
    features: Dict[str, Any] = {}
    output_csv_path: str | None = None
    filename = os.path.basename(input_file_path)
    start_time = time.time()

    try:
        print(f"[INFO] Processing: {filename}")
        pe_analyzer = PEFileAn(input_file_path)
        features = pe_analyzer.build()

        features['isSigned'] = _is_signed(input_file_path)
        features['isPacked'] = _is_packed(input_file_path)

        capabilities_rules = compile_yara_rules(CAPABILITIES_RULES_FILE)
        if capabilities_rules:
            try:
                matched = capabilities_rules.match(input_file_path)
                matched_names = [m.rule for m in matched if hasattr(m, 'rule')]
                for cap in all_capabilities:
                    features[cap] = int(cap in matched_names)
            except yara.Error as e:
                print(f"[WARN] YARA matching error (capabilities) for {filename}: {e}")
                for cap in all_capabilities: features[cap] = -1
            except Exception as e:
                print(f"[WARN] Failed to match capabilities rules for {filename}: {e}")
                for cap in all_capabilities: features[cap] = -1
        else:
             print("[WARN] Capabilities YARA rules not compiled/loaded. Skipping capabilities check.")
             for cap in all_capabilities: features[cap] = -1

        # --- CSV 파일 저장 (지정된 열 순서 적용) ---
        output_dir = os.path.dirname(input_file_path)
        output_csv_filename = f"{filename}_features.csv"
        output_csv_path = os.path.join(output_dir, output_csv_filename)

        # <<<<< 사용자가 요청한 열 순서 정의 >>>>>
        # 사용자가 제공한 리스트를 여기에 정의합니다.
        desired_column_order = [
            "filename", "sha256", "isSigned", "isPacked", "MajorLinkerVersion",
            "MinorLinkerVersion", "SizeOfUninitializedData", "ImageBase", "FileAlignment",
            "MajorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion",
            "MajorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum",
            "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfHeapReserve",
            "NumberOfSections", "e_cblp", "e_lfanew", "SizeOfRawData",
            "Characteristics", "Misc", "BaseOfData", 'inject_thread', 'create_process',
            'persistence', 'hijack_network', 'create_service', 'create_com_service',
            'network_udp_sock', 'network_tcp_listen', 'network_dyndns', 'network_toredo',
            'network_smtp_dotNet', 'network_smtp_raw', 'network_smtp_vb',
            'network_p2p_win', 'network_tor', 'network_irc', 'network_http',
            'network_dropper', 'network_ftp', 'network_tcp_socket', 'network_dns',
            'network_ssl', 'network_dga', 'bitcoin', 'certificate', 'escalate_priv',
            'screenshot', 'lookupip', 'dyndns', 'lookupgeo', 'keylogger',
            'cred_local', 'sniff_audio', 'cred_ff', 'cred_vnc', 'cred_ie7',
            'sniff_lan', 'migrate_apc', 'spreading_file', 'spreading_share',
            'rat_vnc', 'rat_rdp', 'rat_telnet', 'rat_webcam', 'win_mutex',
            'win_registry', 'win_token', 'win_private_profile', 'win_files_operation',
            'Str_Win32_Winsock2_Library', 'Str_Win32_Wininet_Library',
            'Str_Win32_Internet_API', 'Str_Win32_Http_API', 'ldpreload',
            'mysql_database_presence', 'has_manifest', 'has_aslr', 'has_tls',
            'has_dep', 'code_integrity', 'supports_cfg', 'suspicious_dbgts'
            # 'processing_time' 은 마지막에 추가될 것이므로 여기에 포함하지 않거나, 필요 시 마지막에 추가
        ]

        try:
            df = pd.DataFrame([features])
            # DataFrame에 실제로 존재하는 열만으로 순서 리스트를 필터링
            columns_to_write = [col for col in desired_column_order if col in df.columns]
            # 만약 desired_column_order에 없는 추가적인 열이 features 딕셔너리에 있다면 그것들도 포함 (선택 사항)
            # remaining_columns = [col for col in df.columns if col not in columns_to_write]
            # df.to_csv(output_csv_path, index=False, columns=columns_to_write + remaining_columns)

            # 필터링된 순서대로 CSV 저장
            df.to_csv(output_csv_path, index=False, columns=columns_to_write)
            print(f"[INFO] Features saved to: {output_csv_path}")
        except Exception as e:
            print(f"[ERROR] Failed to save features to CSV for {filename}: {e}")
            output_csv_path = None # 저장 실패

    except (ValueError, FileNotFoundError) as e:
        print(f"[ERROR] Error initializing PEFileAn for {filename}: {e}")
        features['error'] = str(e)
    except Exception as e:
        print(f"[ERROR] Unexpected error processing {filename}: {e}")
        features['error'] = str(e)

    end_time = time.time()
    # processing_time은 CSV 저장 후 추가 (CSV 컬럼 순서에 영향을 주지 않음)
    features['processing_time'] = round(end_time - start_time, 3)

    return features, output_csv_path
