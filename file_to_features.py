# file_to_features.py

import os
import time
import pandas as pd
import datetime
import hashlib
import pefile # type: ignore
import lief # type: ignore
import yara # type: ignore
from signify.authenticode import SignedPEFile # type: ignore
from typing import Dict, Any, List, Tuple
from functools import lru_cache

# ====== 설정 (YARA 룰 경로) ======
YARA_RULES_DIR = "yara_rules" # yara_rules 폴더는 프로젝트 루트에 위치해야 함
CAPABILITIES_RULES_FILE = os.path.join(YARA_RULES_DIR, 'capabilities.yar')
PACKER_RULES_FILE = os.path.join(YARA_RULES_DIR, 'packer_compiler_signatures.yar')

# ====== YARA 룰 컴파일 함수 (캐싱 사용) ======
@lru_cache(maxsize=2) # 최대 2개 룰셋 캐싱
def compile_yara_rules(filepath: str):
    """주어진 경로의 YARA 룰을 컴파일합니다. 실패 시 None 반환 및 경고 출력."""
    try:
        if not os.path.exists(filepath):
            print(f"[WARN] YARA rule file not found: {filepath}. Rule matching will be skipped.")
            return None
        compiled_rules = yara.compile(filepath=filepath)
        print(f"[INFO] YARA rule compiled successfully: {filepath}")
        return compiled_rules
    except yara.Error as e: # yara.Error를 명시적으로 처리
        print(f"[ERROR] Failed to compile YARA rule {filepath}: {e}")
        return None
    except Exception as e: # 그 외 일반적인 예외
        print(f"[ERROR] An unexpected error occurred while compiling YARA rule {filepath}: {e}")
        return None

# ====== Capabilities 정의 ======
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

# ====== 특징 추출 헬퍼 함수들 (PEFileAn 클래스 외부로 분리) ======
def _get_characteristics_list(binary: lief.PE.Binary) -> List[str]:
    try:
        if (binary and hasattr(binary, 'optional_header') and
                isinstance(binary.optional_header, lief.PE.OptionalHeader) and
                hasattr(binary.optional_header, 'dll_characteristics') and
                isinstance(binary.optional_header.dll_characteristics, list)):
            return [str(x).split('.')[-1] for x in binary.optional_header.dll_characteristics]
        return []
    except Exception as e:
        print(f"[WARN] Helper: Failed to get characteristics list for {binary.name if binary else 'binary'}: {e}")
        return []

def _suspicious_dbgts(binary: lief.PE.Binary) -> int: # 이 함수는 유지
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
        print(f"[WARN] Helper: Debug timestamp value out of range for {binary.name if binary else 'binary'}.")
        return -1
    except Exception as e:
        print(f"[WARN] Helper: Failed to check debug timestamp for {binary.name if binary else 'binary'}: {e}")
        return -1

def _is_signed(filename: str) -> int:
    try:
        with open(filename, "rb") as f:
            signed_pe = SignedPEFile(f)
            status, _ = signed_pe.explain_verify()
            return {1: 1, 2: 0}.get(status.value, -1)
    except Exception as e:
        print(f"[WARN] Helper: Failed to check signature for {os.path.basename(filename)}: {e}")
        return -1

def _is_packed(filename: str) -> int:
    packer_rules = compile_yara_rules(PACKER_RULES_FILE)
    if packer_rules is None:
        return -1
    try:
        matches = packer_rules.match(filename)
        return int('IsPacked' in [m.rule for m in matches if hasattr(m, 'rule')])
    except yara.Error as e:
        print(f"[WARN] Helper: YARA matching error (packer) for {os.path.basename(filename)}: {e}")
        return -1
    except Exception as e:
        print(f"[WARN] Helper: Failed to check packing for {os.path.basename(filename)}: {e}")
        return -1

def _calculate_sha256(filename: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Helper: Failed to calculate SHA256 for {os.path.basename(filename)}: {e}")
        return "error_calculating_hash"

# ====== PEFile 분석 클래스 (사용자 제공 코드 기반) ======
class PEFileAn:
    def __init__(self, filename_path: str):
        self.features: Dict[str, Any] = {}
        self.filename = os.path.basename(filename_path)
        self.features['filename'] = self.filename

        binary: lief.PE.Binary | None = None
        pe: pefile.PE | None = None

        try:
            print(f"[INFO] PEFileAn: Parsing {self.filename} with lief...")
            binary = lief.parse(filename_path)
            if binary is None:
                print(f"[WARN] PEFileAn: Lief parse failed for {self.filename}.")
        except lief.bad_file as e:
            print(f"[WARN] PEFileAn: Lief bad_file error for {self.filename}: {e}")
        except FileNotFoundError:
            print(f"[ERROR] PEFileAn: Input file not found for lief: {filename_path}")
            raise
        except Exception as e:
            print(f"[WARN] PEFileAn: Error parsing with lief for {self.filename}: {e}")

        try:
            print(f"[INFO] PEFileAn: Loading {self.filename} with pefile...")
            pe = pefile.PE(filename_path, fast_load=False)
        except pefile.PEFormatError as e:
            print(f"[WARN] PEFileAn: pefile PEFormatError for {self.filename}: {e}")
        except FileNotFoundError:
            print(f"[ERROR] PEFileAn: Input file not found for pefile: {filename_path}")
            raise
        except Exception as e:
            print(f"[WARN] PEFileAn: Error loading with pefile for {self.filename}: {e}")

        self.features['sha256'] = _calculate_sha256(filename_path)
        self.features['isSigned'] = _is_signed(filename_path)
        self.features['isPacked'] = _is_packed(filename_path)

        if pe and hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
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
            if pe: print(f"[WARN] PEFileAn: Optional Header not found or invalid in {self.filename}")
            optional_header_fields = ['MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfUninitializedData', 'ImageBase', 'FileAlignment', 'MajorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfHeapReserve', 'BaseOfData']
            for field in optional_header_fields: self.features.setdefault(field, 0)

        if pe and hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
            file_header = pe.FILE_HEADER
            self.features['NumberOfSections'] = getattr(file_header, 'NumberOfSections', 0)
            self.features['Characteristics'] = getattr(file_header, 'Characteristics', 0)
        else:
            if pe: print(f"[WARN] PEFileAn: File Header not found or invalid in {self.filename}")
            self.features.setdefault('NumberOfSections', 0)
            self.features.setdefault('Characteristics', 0)

        if pe and hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER:
            dos_header = pe.DOS_HEADER
            self.features['e_cblp'] = getattr(dos_header, 'e_cblp', 0)
            self.features['e_lfanew'] = getattr(dos_header, 'e_lfanew', 0)
        else:
             if pe: print(f"[WARN] PEFileAn: DOS Header not found or invalid in {self.filename}")
             self.features.setdefault('e_cblp', 0)
             self.features.setdefault('e_lfanew', 0)

        try:
            if pe and hasattr(pe, 'sections') and isinstance(pe.sections, list) and pe.sections:
                self.features['SizeOfRawData'] = sum(getattr(s, 'SizeOfRawData', 0) for s in pe.sections)
                self.features['Misc'] = sum(getattr(s, 'Misc_VirtualSize', 0) for s in pe.sections)
            else:
                self.features.setdefault('SizeOfRawData', 0)
                self.features.setdefault('Misc', 0)
        except Exception as e:
            print(f"[WARN] PEFileAn: Error calculating section features for {self.filename}: {e}")
            self.features.setdefault('SizeOfRawData', 0)
            self.features.setdefault('Misc', 0)

        capabilities_rules = compile_yara_rules(CAPABILITIES_RULES_FILE)
        if capabilities_rules:
            try:
                matched = capabilities_rules.match(filename_path)
                matched_names = [m.rule for m in matched if hasattr(m, 'rule')]
                for cap in all_capabilities:
                    self.features[cap] = int(cap in matched_names)
            except yara.Error as e:
                print(f"[WARN] PEFileAn: YARA matching error (capabilities) for {self.filename}: {e}")
                for cap in all_capabilities: self.features.setdefault(cap, -1)
            except Exception as e:
                print(f"[WARN] PEFileAn: Failed to match capabilities rules for {self.filename}: {e}")
                for cap in all_capabilities: self.features.setdefault(cap, -1)
        else:
             print("[WARN] PEFileAn: Capabilities YARA rules not compiled/loaded. Skipping capabilities check.")
             for cap in all_capabilities: self.features.setdefault(cap, -1)

        # 추가 분석 플래그 (lief 사용) 
        if binary:
            self.features['suspicious_dbgts'] = _suspicious_dbgts(binary) # 이 특징은 유지
        else:
            # lief_flags = ['has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg', 'suspicious_dbgts'] # 수정
            lief_flags = ['has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg']
            for flag in lief_flags:
                self.features.setdefault(flag, -1) # 제거된 특징들도 기본값 -1로 설정 (CSV 컬럼 유지 시)
                                                   # 또는 아예 features 딕셔너리에 추가하지 않을 수도 있음
            self.features.setdefault('suspicious_dbgts', -1)


        if pe and hasattr(pe, 'close'):
            try:
                pe.close()
            except Exception as close_e:
                 print(f"[WARN] PEFileAn: Error closing pefile object for {self.filename}: {close_e}")

    def build(self) -> Dict[str, Any]:
        return self.features

# ====== 메인 특징 추출 및 저장 함수 (기존 프로젝트 구조와 호환) ======
def extract_features_for_file(input_file_path: str) -> Tuple[Dict[str, Any], str | None]:
    features: Dict[str, Any] = {}
    output_csv_path: str | None = None
    filename = os.path.basename(input_file_path)
    start_time = time.time()

    try:
        print(f"[INFO] extract_features_for_file: Processing {filename}")
        pe_analyzer = PEFileAn(input_file_path)
        features = pe_analyzer.build()

        output_dir = os.path.dirname(input_file_path)
        output_csv_filename = f"{filename}_features.csv"
        output_csv_path = os.path.join(output_dir, output_csv_filename)

        desired_column_order = [
            "filename", "sha256", "isSigned", "isPacked", "MajorLinkerVersion",
            "MinorLinkerVersion", "SizeOfUninitializedData", "ImageBase", "FileAlignment",
            "MajorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion",
            "MajorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum",
            "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfHeapReserve",
            "NumberOfSections", "e_cblp", "e_lfanew", "SizeOfRawData",
            "Characteristics", "Misc", "BaseOfData"
        ] + all_capabilities + [
            # 'has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg', # 제거
            'suspicious_dbgts' # 이 특징은 유지
        ]

        try:
            df = pd.DataFrame([features])
            columns_to_write = [col for col in desired_column_order if col in df.columns]
            df.to_csv(output_csv_path, index=False, columns=columns_to_write)
            print(f"[INFO] Features saved to: {output_csv_path}")
        except Exception as e:
            print(f"[ERROR] Failed to save features to CSV for {filename}: {e}")
            output_csv_path = None

    except (ValueError, FileNotFoundError) as e:
        print(f"[ERROR] Error initializing PEFileAn for {filename}: {e}")
        features['error'] = str(e)
    except Exception as e:
        print(f"[ERROR] Unexpected error processing {filename}: {e}")
        features['error'] = str(e)

    end_time = time.time()
    features['processing_time'] = round(end_time - start_time, 3)

    return features, output_csv_path
