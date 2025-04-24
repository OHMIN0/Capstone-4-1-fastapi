# file_to_features.py

import os
import time
import pandas as pd
import datetime
import hashlib
import pefile
import lief
import yara # yara 임포트는 유지
from signify.authenticode import SignedPEFile
from typing import Dict, Any, List, Tuple
from functools import lru_cache # 간단한 캐싱을 위해 추가

# ====== 설정 (YARA 룰 경로) ======
YARA_RULES_DIR = "yara_rules"
CAPABILITIES_RULES_FILE = os.path.join(YARA_RULES_DIR, 'capabilities.yar')
PACKER_RULES_FILE = os.path.join(YARA_RULES_DIR, 'packer_compiler_signatures.yar')

# ====== YARA 룰 컴파일 함수 (캐싱 사용) ======
# 동일한 파일을 반복해서 컴파일하는 것을 방지하기 위해 LRU 캐시 사용
@lru_cache(maxsize=2) # 최대 2개 룰셋 캐싱 (capabilities, packer)
def compile_yara_rules(filepath: str):
    """주어진 경로의 YARA 룰을 컴파일합니다. 실패 시 None 반환 및 경고 출력."""
    try:
        # Dockerfile에서 yara_rules 폴더를 복사했는지 확인 필요
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
# (사용자가 제공한 리스트)
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

# ====== 특징 추출 헬퍼 함수들 (안정성 개선) ======
# (이전 '개선됨' 버전의 함수들 사용)
def get_characteristics_list(binary: lief.PE.Binary) -> List[str]:
    """lief 바이너리 객체에서 DLL 특성 리스트를 문자열로 반환합니다."""
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

def has_manifest(binary: lief.PE.Binary) -> int:
    """리소스 매니저와 매니페스트 존재 여부를 반환합니다."""
    try:
        return int(binary and binary.has_resources and hasattr(binary, 'resources_manager') and binary.resources_manager.has_manifest)
    except Exception as e:
        print(f"[WARN] Failed to check manifest: {e}")
        return -1

def has_aslr(binary: lief.PE.Binary) -> int:
    """ASLR 지원 여부를 반환합니다."""
    return int("DYNAMIC_BASE" in get_characteristics_list(binary))

def has_tls(binary: lief.PE.Binary) -> int:
    """TLS 사용 여부를 반환합니다."""
    try:
        return int(binary and binary.has_tls)
    except Exception as e:
        print(f"[WARN] Failed to check TLS: {e}")
        return -1

def has_dep(binary: lief.PE.Binary) -> int:
    """DEP 지원 여부를 반환합니다."""
    return int("NX_COMPAT" in get_characteristics_list(binary))

def check_ci(binary: lief.PE.Binary) -> int:
    """Code Integrity 확인."""
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

def supports_cfg(binary: lief.PE.Binary) -> int:
    """Control Flow Guard 지원 여부를 반환합니다."""
    return int("GUARD_CF" in get_characteristics_list(binary))

def suspicious_dbgts(binary: lief.PE.Binary) -> int:
    """디버그 타임스탬프가 미래 시점인지 확인합니다."""
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
        print(f"[WARN] Debug timestamp value out of range for {binary.name if binary else 'binary'}.")
        return -1
    except Exception as e:
        print(f"[WARN] Failed to check debug timestamp for {binary.name if binary else 'binary'}: {e}")
        return -1

def is_signed(filename: str) -> int:
    """signify 라이브러리를 사용하여 파일 서명 여부를 확인합니다."""
    try:
        with open(filename, "rb") as f:
            signed_pe = SignedPEFile(f)
            return 1 if signed_pe.signed else 0
    except Exception as e:
        print(f"[WARN] Failed to check signature for {os.path.basename(filename)}: {e}")
        return -1

def is_packed(filename: str) -> int:
    """YARA 룰을 사용하여 패킹 여부를 확인합니다 (내부에서 룰 컴파일)."""
    packer_rules = compile_yara_rules(PACKER_RULES_FILE)
    if packer_rules is None:
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

def calculate_sha256(filename: str) -> str:
    """파일의 SHA256 해시를 계산합니다."""
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to calculate SHA256 for {os.path.basename(filename)}: {e}")
        return "error_calculating_hash"

# ====== 메인 특징 추출 및 저장 함수 ======
def extract_features_for_file(input_file_path: str) -> Tuple[Dict[str, Any], str | None]:
    """
    주어진 단일 PE 파일 경로로부터 특징을 추출하고, 결과를 딕셔너리로 반환하며,
    동일 디렉토리에 CSV 파일로 저장합니다. (지정된 열 순서 적용)
    """
    features: Dict[str, Any] = {}
    output_csv_path: str | None = None
    filename = os.path.basename(input_file_path)
    start_time = time.time() # 함수 시작 시간 기록

    # Capabilities 룰 컴파일 시도 (함수 호출 시)
    capabilities_rules = compile_yara_rules(CAPABILITIES_RULES_FILE)

    try:
        print(f"[INFO] Processing: {filename}")
        binary: lief.PE.Binary | None = None # lief 객체 초기화
        pe: pefile.PE | None = None # pefile 객체 초기화

        # lief와 pefile 객체 생성 시도 (오류 발생 시에도 특징 추출 계속 시도)
        try:
            binary = lief.parse(input_file_path)
            if binary is None:
                 print(f"[WARN] Lief parse failed for {filename}.")
        except lief.bad_file as e:
             print(f"[WARN] Lief bad_file error for {filename}: {e}")
        except FileNotFoundError:
             print(f"[ERROR] Input file not found for lief: {input_file_path}")
             raise # 파일 없음은 계속 진행 불가
        except Exception as e:
             print(f"[WARN] Error parsing with lief for {filename}: {e}")

        try:
            pe = pefile.PE(input_file_path, fast_load=False)
        except pefile.PEFormatError as e:
            print(f"[WARN] pefile PEFormatError for {filename}: {e}")
        except FileNotFoundError:
             print(f"[ERROR] Input file not found for pefile: {input_file_path}")
             raise # 파일 없음은 계속 진행 불가
        except Exception as e:
            print(f"[WARN] Error loading with pefile for {filename}: {e}")

        # --- 특징 추출 시작 ---
        features['filename'] = filename
        features['sha256'] = calculate_sha256(input_file_path)
        features['isSigned'] = is_signed(input_file_path)
        features['isPacked'] = is_packed(input_file_path) # 함수 내부에서 packer 룰 컴파일

        # PE header features (pefile 사용)
        if pe and hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
            opt_header = pe.OPTIONAL_HEADER
            features['MajorLinkerVersion'] = getattr(opt_header, 'MajorLinkerVersion', 0)
            features['MinorLinkerVersion'] = getattr(opt_header, 'MinorLinkerVersion', 0)
            # ... (기타 Optional Header 필드) ...
            features['SizeOfUninitializedData'] = getattr(opt_header, 'SizeOfUninitializedData', 0)
            features['ImageBase'] = getattr(opt_header, 'ImageBase', 0)
            features['FileAlignment'] = getattr(opt_header, 'FileAlignment', 0)
            features['MajorOperatingSystemVersion'] = getattr(opt_header, 'MajorOperatingSystemVersion', 0)
            features['MajorImageVersion'] = getattr(opt_header, 'MajorImageVersion', 0)
            features['MinorImageVersion'] = getattr(opt_header, 'MinorImageVersion', 0)
            features['MajorSubsystemVersion'] = getattr(opt_header, 'MajorSubsystemVersion', 0)
            features['SizeOfImage'] = getattr(opt_header, 'SizeOfImage', 0)
            features['SizeOfHeaders'] = getattr(opt_header, 'SizeOfHeaders', 0)
            features['CheckSum'] = getattr(opt_header, 'CheckSum', 0)
            features['Subsystem'] = getattr(opt_header, 'Subsystem', 0)
            features['DllCharacteristics'] = getattr(opt_header, 'DllCharacteristics', 0)
            features['SizeOfStackReserve'] = getattr(opt_header, 'SizeOfStackReserve', 0)
            features['SizeOfHeapReserve'] = getattr(opt_header, 'SizeOfHeapReserve', 0)
            features['BaseOfData'] = getattr(opt_header, 'BaseOfData', 0)
        else:
            if pe: print(f"[WARN] Optional Header not found or invalid in {filename}")
            optional_header_fields = ['MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfUninitializedData', 'ImageBase', 'FileAlignment', 'MajorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfHeapReserve', 'BaseOfData']
            for field in optional_header_fields: features.setdefault(field, 0)

        if pe and hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
            file_header = pe.FILE_HEADER
            features['NumberOfSections'] = getattr(file_header, 'NumberOfSections', 0)
            features['Characteristics'] = getattr(file_header, 'Characteristics', 0)
        else:
            if pe: print(f"[WARN] File Header not found or invalid in {filename}")
            features.setdefault('NumberOfSections', 0)
            features.setdefault('Characteristics', 0)

        if pe and hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER:
            dos_header = pe.DOS_HEADER
            features['e_cblp'] = getattr(dos_header, 'e_cblp', 0)
            features['e_lfanew'] = getattr(dos_header, 'e_lfanew', 0)
        else:
             if pe: print(f"[WARN] DOS Header not found or invalid in {filename}")
             features.setdefault('e_cblp', 0)
             features.setdefault('e_lfanew', 0)

        try:
            if pe and hasattr(pe, 'sections') and isinstance(pe.sections, list) and pe.sections:
                features['SizeOfRawData'] = sum(getattr(s, 'SizeOfRawData', 0) for s in pe.sections)
                features['Misc'] = sum(getattr(s, 'Misc_VirtualSize', 0) for s in pe.sections)
            else:
                features.setdefault('SizeOfRawData', 0)
                features.setdefault('Misc', 0)
        except Exception as e:
            print(f"[WARN] Error calculating section features for {filename}: {e}")
            features.setdefault('SizeOfRawData', 0)
            features.setdefault('Misc', 0)

        # Capabilities via YARA (컴파일된 룰 객체 사용)
        if capabilities_rules: # 룰 컴파일 성공 시에만 실행
            try:
                matched = capabilities_rules.match(input_file_path)
                matched_names = [m.rule for m in matched if hasattr(m, 'rule')]
                for cap in all_capabilities:
                    features.setdefault(cap, int(cap in matched_names))
            except yara.Error as e:
                print(f"[WARN] YARA matching error (capabilities) for {filename}: {e}")
                for cap in all_capabilities: features.setdefault(cap, -1)
            except Exception as e:
                print(f"[WARN] Failed to match capabilities rules for {filename}: {e}")
                for cap in all_capabilities: features.setdefault(cap, -1)
        else:
             print("[WARN] Capabilities YARA rules not compiled/loaded. Skipping capabilities check.")
             for cap in all_capabilities: features.setdefault(cap, -1)

        # 추가 분석 플래그 (lief 사용, binary 객체 None 체크 추가)
        if binary:
            features['has_manifest'] = has_manifest(binary)
            features['has_aslr'] = has_aslr(binary)
            features['has_tls'] = has_tls(binary)
            features['has_dep'] = has_dep(binary)
            features['code_integrity'] = check_ci(binary)
            features['supports_cfg'] = supports_cfg(binary)
            features['suspicious_dbgts'] = suspicious_dbgts(binary)
        else:
            # lief 파싱 실패 시 기본값 -1 설정
            lief_flags = ['has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg', 'suspicious_dbgts']
            for flag in lief_flags: features.setdefault(flag, -1)

        # --- 특징 추출 완료 ---

        # --- CSV 파일 저장 (지정된 열 순서 적용) ---
        output_dir = os.path.dirname(input_file_path)
        output_csv_filename = f"{filename}_features.csv"
        output_csv_path = os.path.join(output_dir, output_csv_filename)

        # CSV 저장 위한 열 순서 정의
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
        ]

        try:
            df = pd.DataFrame([features])
            columns_to_write = [col for col in desired_column_order if col in df.columns]
            df.to_csv(output_csv_path, index=False, columns=columns_to_write)
            print(f"[INFO] Features saved to: {output_csv_path}")
        except Exception as e:
            print(f"[ERROR] Failed to save features to CSV for {filename}: {e}")
            output_csv_path = None # 저장 실패

    except (ValueError, FileNotFoundError) as e: # 파일 없음 또는 파싱 불가 오류
        print(f"[ERROR] Cannot process file {filename}: {e}")
        features['error'] = str(e) # 오류 정보 추가
    except Exception as e: # 기타 예외 처리
        print(f"[ERROR] Unexpected error processing {filename}: {e}")
        features['error'] = str(e)
    finally:
        # pefile 객체 닫기 (생성 성공 시)
        if 'pe' in locals() and pe and hasattr(pe, 'close'):
            try: pe.close()
            except Exception as close_e: print(f"[WARN] Error closing pefile object: {close_e}")

    # 처리 시간은 CSV 저장 후 features 딕셔너리에 추가
    end_time = time.time()
    features['processing_time'] = round(end_time - start_time, 3)

    # 최종적으로 특징 딕셔너리와 CSV 경로 반환
    return features, output_csv_path
