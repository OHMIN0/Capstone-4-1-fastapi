# file_to_features.py

import os
import pandas as pd
import datetime
import hashlib
import pefile
import lief
import yara
from signify.authenticode import SignedPEFile
from typing import Dict, Any, List, Tuple
from functools import lru_cache # YARA 룰 컴파일 캐싱 위해 사용

# ====== 설정 (YARA 룰 경로) ======
# 프로젝트 루트에 'yara_rules' 폴더가 있다고 가정합니다.
YARA_RULES_DIR = "yara_rules"
CAPABILITIES_RULES_FILE = os.path.join(YARA_RULES_DIR, 'capabilities.yar')
PACKER_RULES_FILE = os.path.join(YARA_RULES_DIR, 'packer_compiler_signatures.yar')

# ====== YARA 룰 컴파일 함수 (캐싱 사용) ======
# 동일한 파일을 반복해서 컴파일하는 것을 방지 (효율성)
@lru_cache(maxsize=2) # capabilities, packer 룰 최대 2개 캐싱
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

# ====== 특징 추출 헬퍼 함수들 (클래스 외부 정의) ======
# PEFileAn 클래스 또는 extract_features_for_file 함수 내부에서 사용됩니다.
def _get_characteristics_list(binary: lief.PE.Binary) -> List[str]:
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

def _has_manifest(binary: lief.PE.Binary) -> int:
    """리소스 매니저와 매니페스트 존재 여부를 반환합니다."""
    try:
        # resources_manager 속성 존재 여부 명시적 확인
        return int(binary and binary.has_resources and hasattr(binary, 'resources_manager') and binary.resources_manager.has_manifest)
    except Exception as e:
        print(f"[WARN] Failed to check manifest: {e}")
        return -1

def _has_aslr(binary: lief.PE.Binary) -> int:
    """ASLR 지원 여부를 반환합니다."""
    return int("DYNAMIC_BASE" in _get_characteristics_list(binary))

def _has_tls(binary: lief.PE.Binary) -> int:
    """TLS 사용 여부를 반환합니다."""
    try:
        return int(binary and binary.has_tls)
    except Exception as e:
        print(f"[WARN] Failed to check TLS: {e}")
        return -1

def _has_dep(binary: lief.PE.Binary) -> int:
    """DEP 지원 여부를 반환합니다."""
    return int("NX_COMPAT" in _get_characteristics_list(binary))

def _check_ci(binary: lief.PE.Binary) -> int:
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

def _supports_cfg(binary: lief.PE.Binary) -> int:
    """Control Flow Guard 지원 여부를 반환합니다."""
    return int("GUARD_CF" in _get_characteristics_list(binary))

def _suspicious_dbgts(binary: lief.PE.Binary) -> int:
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

def _is_signed(filename: str) -> int:
    """signify 라이브러리를 사용하여 파일 서명 여부를 확인합니다."""
    try:
        with open(filename, "rb") as f:
            signed_pe = SignedPEFile(f)
            # 서명 존재 여부만 확인 (더 빠름)
            return 1 if signed_pe.signed else 0
    except Exception as e:
        # 서명 관련 라이브러리 오류 시 -1 반환
        print(f"[WARN] Failed to check signature for {os.path.basename(filename)}: {e}")
        return -1

def _is_packed(filename: str) -> int:
    """YARA 룰을 사용하여 패킹 여부를 확인합니다 (내부에서 룰 컴파일)."""
    packer_rules = compile_yara_rules(PACKER_RULES_FILE)
    if packer_rules is None:
        return -1 # 룰 로드/컴파일 실패
    try:
        matches = packer_rules.match(filename)
        # 'packer' 태그 확인 (룰 파일 확인 필요)
        return int(any(m.tags and 'packer' in m.tags for m in matches))
    except yara.Error as e:
        print(f"[WARN] YARA matching error (packer) for {os.path.basename(filename)}: {e}")
        return -1
    except Exception as e:
        print(f"[WARN] Failed to check packing for {os.path.basename(filename)}: {e}")
        return -1

def _calculate_sha256(filename: str) -> str:
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

# ====== PEFile 분석 클래스 (수정됨) ======
class PEFileAn:
    """
    주어진 PE 파일 경로를 사용하여 lief 및 pefile 객체를 로드하고,
    기본적인 헤더 특징 및 lief 기반 플래그들을 추출합니다.
    """
    def __init__(self, filename: str):
        self.filename = filename
        self.basename = os.path.basename(filename)
        self.features: Dict[str, Any] = {'filename': self.basename}
        self.binary: lief.PE.Binary | None = None
        self.pe: pefile.PE | None = None

        # lief와 pefile 객체 생성 시도
        try:
            self.binary = lief.parse(filename)
            if self.binary is None:
                 # lief 파싱 실패 시 None 유지, 오류는 호출자에게 전파하지 않음
                 print(f"[WARN] Lief parse failed for {self.basename} (not a PE file or corrupted?).")
        except lief.bad_file as e:
             print(f"[WARN] Lief bad_file error for {self.basename}: {e}")
        except FileNotFoundError:
             print(f"[ERROR] Input file not found for lief: {filename}")
             raise # 파일 없음은 심각한 오류이므로 전파
        except Exception as e:
             print(f"[WARN] Error parsing with lief for {self.basename}: {e}")

        try:
            self.pe = pefile.PE(filename, fast_load=False)
        except pefile.PEFormatError as e:
            print(f"[WARN] pefile PEFormatError for {self.basename}: {e}")
        except FileNotFoundError:
             print(f"[ERROR] Input file not found for pefile: {filename}")
             raise # 파일 없음은 심각한 오류이므로 전파
        except Exception as e:
            print(f"[WARN] Error loading with pefile for {self.basename}: {e}")

        # 객체 로딩 성공 여부와 관계없이 특징 추출 시도 (실패 시 기본값 사용)
        self._extract_base_features()

    def _extract_base_features(self):
        """pefile과 lief 객체를 사용하여 기본 특징 추출"""
        pe = self.pe
        binary = self.binary

        self.features['sha256'] = _calculate_sha256(self.filename)

        # PE header features (pefile 사용)
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
            if pe: print(f"[WARN] Optional Header not found or invalid in {self.basename}")
            optional_header_fields = ['MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfUninitializedData', 'ImageBase', 'FileAlignment', 'MajorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfHeapReserve', 'BaseOfData']
            for field in optional_header_fields: self.features.setdefault(field, 0) # setdefault 사용

        if pe and hasattr(pe, 'FILE_HEADER') and pe.FILE_HEADER:
            file_header = pe.FILE_HEADER
            self.features['NumberOfSections'] = getattr(file_header, 'NumberOfSections', 0)
            self.features['Characteristics'] = getattr(file_header, 'Characteristics', 0)
        else:
            if pe: print(f"[WARN] File Header not found or invalid in {self.basename}")
            self.features.setdefault('NumberOfSections', 0)
            self.features.setdefault('Characteristics', 0)

        if pe and hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER:
            dos_header = pe.DOS_HEADER
            self.features['e_cblp'] = getattr(dos_header, 'e_cblp', 0)
            self.features['e_lfanew'] = getattr(dos_header, 'e_lfanew', 0)
        else:
             if pe: print(f"[WARN] DOS Header not found or invalid in {self.basename}")
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
            print(f"[WARN] Error calculating section features for {self.basename}: {e}")
            self.features.setdefault('SizeOfRawData', 0)
            self.features.setdefault('Misc', 0)

        # 추가 분석 플래그 (lief 사용)
        if binary: # lief 파싱 성공 시에만 시도
            self.features['has_manifest'] = _has_manifest(binary)
            self.features['has_aslr'] = _has_aslr(binary)
            self.features['has_tls'] = _has_tls(binary)
            self.features['has_dep'] = _has_dep(binary)
            self.features['code_integrity'] = _check_ci(binary)
            self.features['supports_cfg'] = _supports_cfg(binary)
            self.features['suspicious_dbgts'] = _suspicious_dbgts(binary)
        else:
            # lief 파싱 실패 시 기본값 -1 설정
            lief_flags = ['has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg', 'suspicious_dbgts']
            for flag in lief_flags: self.features.setdefault(flag, -1)

        # pefile 객체 닫기 (생성 성공 시)
        if pe and hasattr(pe, 'close'):
            try: pe.close()
            except Exception as close_e: print(f"[WARN] Error closing pefile object: {close_e}")

    def build(self) -> Dict[str, Any]:
        """추출된 특징 딕셔너리를 반환합니다."""
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

        # PEFileAn 클래스 인스턴스 생성 (내부에서 파일 파싱 및 기본 특징 추출)
        # 파일 없음 등의 심각한 오류 시 여기서 예외 발생 가능
        pe_analyzer = PEFileAn(input_file_path)
        features = pe_analyzer.build() # 기본 특징 가져오기

        # 추가 특징 추출 (YARA, Signify)
        features['isSigned'] = _is_signed(input_file_path)
        features['isPacked'] = _is_packed(input_file_path) # 함수 내부에서 packer 룰 컴파일

        # Capabilities via YARA
        capabilities_rules = compile_yara_rules(CAPABILITIES_RULES_FILE) # capabilities 룰 컴파일
        if capabilities_rules:
            try:
                matched = capabilities_rules.match(input_file_path)
                matched_names = [m.rule for m in matched if hasattr(m, 'rule')]
                for cap in all_capabilities:
                    # setdefault 를 사용하여 키가 없는 경우에도 오류 없이 0으로 설정
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
            # features 딕셔너리에 없는 키가 desired_column_order에 있을 수 있으므로,
            # DataFrame 생성 시 모든 키를 포함하도록 처리 (값이 없으면 NaN -> 추후 처리 필요)
            # 또는, 저장 시 columns 인자를 사용하여 존재하는 키만 저장
            df = pd.DataFrame([features])
            # 실제 존재하는 컬럼만 desired_column_order 순서에 맞게 필터링
            columns_to_write = [col for col in desired_column_order if col in df.columns]
            # 만약 features 딕셔너리에 desired_column_order에 없는 키가 있다면 추가 (선택 사항)
            # extra_cols = [col for col in df.columns if col not in columns_to_write]
            # columns_to_write.extend(extra_cols)

            df.to_csv(output_csv_path, index=False, columns=columns_to_write)
            print(f"[INFO] Features saved to: {output_csv_path}")
        except Exception as e:
            print(f"[ERROR] Failed to save features to CSV for {filename}: {e}")
            output_csv_path = None # 저장 실패

    except (ValueError, FileNotFoundError) as e: # PEFileAn 초기화 중 발생한 오류
        print(f"[ERROR] Error initializing PEFileAn for {filename}: {e}")
        features['error'] = str(e) # 오류 정보 추가
    except Exception as e: # 기타 예외 처리
        print(f"[ERROR] Unexpected error processing {filename}: {e}")
        features['error'] = str(e)

    # 처리 시간은 CSV 저장 후 features 딕셔너리에 추가 (CSV 내용에는 영향 없음)
    end_time = time.time()
    features['processing_time'] = round(end_time - start_time, 3)

    # 최종적으로 특징 딕셔너리와 CSV 경로 반환
    return features, output_csv_path
