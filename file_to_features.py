# file_2_feature.py

import os
import pandas as pd
import datetime
import hashlib
import pefile
import lief
import yara
from signify.authenticode import SignedPEFile
from typing import Dict, Any, List, Tuple

# ====== 설정 (YARA 룰 경로) ======
# 프로젝트 루트에 'yara_rules' 폴더가 있다고 가정합니다.
YARA_RULES_DIR = "yara_rules"
CAPABILITIES_RULES_FILE = os.path.join(YARA_RULES_DIR, 'capabilities.yar')
PACKER_RULES_FILE = os.path.join(YARA_RULES_DIR, 'packer_compiler_signatures.yar')

# ====== YARA 룰 컴파일 (오류 처리 추가) ======
try:
    if not os.path.exists(CAPABILITIES_RULES_FILE):
        raise FileNotFoundError(f"YARA rule file not found: {CAPABILITIES_RULES_FILE}")
    if not os.path.exists(PACKER_RULES_FILE):
        raise FileNotFoundError(f"YARA rule file not found: {PACKER_RULES_FILE}")

    capabilities_rules = yara.compile(filepath=CAPABILITIES_RULES_FILE)
    packer_rules = yara.compile(filepath=PACKER_RULES_FILE)
    print("[INFO] YARA rules compiled successfully.")
except Exception as e:
    print(f"[ERROR] Failed to compile YARA rules: {e}")
    # 실제 운영 환경에서는 YARA 룰 로딩 실패 시 처리를 결정해야 합니다.
    # 예: 기본값 반환, 프로그램 종료 등
    capabilities_rules = None
    packer_rules = None

# ====== Capabilities 정의 ======
# (원본 코드와 동일)
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

# ====== 특징 추출 헬퍼 함수들 (클래스 외부 또는 정적 메소드로 분리) ======
def get_characteristics_list(binary: lief.PE.Binary) -> List[str]:
    """lief 바이너리 객체에서 DLL 특성 리스트를 문자열로 반환합니다."""
    try:
        # lief 버전 호환성 고려 (OptionalHeader 타입 체크)
        if binary and isinstance(binary.optional_header, lief.PE.OptionalHeader):
             # OptionalHeader.dll_characteristics_lists 가 아니라 dll_characteristics 임
            return [str(x).split('.')[-1] for x in binary.optional_header.dll_characteristics]
        return []
    except Exception as e:
        print(f"[WARN] Failed to get characteristics list: {e}")
        return []

def has_manifest(binary: lief.PE.Binary) -> int:
    """리소스 매니저와 매니페스트 존재 여부를 반환합니다."""
    try:
        # lief 버전 호환성 고려
        return int(binary and binary.has_resources and binary.has_resources_manager and binary.resources_manager.has_manifest)
    except Exception as e:
        print(f"[WARN] Failed to check manifest: {e}")
        return -1 # 오류 시 -1 반환

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
    """Code Integrity 확인 (LoadConfigurationV2 이상 필요)."""
    try:
        if binary and binary.has_configuration:
             # lief 버전 호환성 고려 (LoadConfiguration 타입 체크)
            config = binary.load_configuration
            if isinstance(config, (lief.PE.LoadConfigurationV2, lief.PE.LoadConfigurationV3, lief.PE.LoadConfigurationV4,
                                    lief.PE.LoadConfigurationV5, lief.PE.LoadConfigurationV6, lief.PE.LoadConfigurationV7,
                                    lief.PE.LoadConfigurationV8, lief.PE.LoadConfigurationV9, lief.PE.LoadConfigurationV10,
                                    lief.PE.LoadConfigurationV11)) and hasattr(config, 'code_integrity'):
                # Catalog 값 확인 방식 수정 (lief 문서 참고 필요)
                # 예시: if config.code_integrity.flags == 특정값: ...
                # 여기서는 단순 존재 여부만 반환 (추후 상세 로직 필요 시 수정)
                return 1 # Code Integrity 정보 존재
            else:
                 return 0 # Code Integrity 정보 없거나 다른 버전
        return -1 # Configuration 정보 없음
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
                if hasattr(item, 'timestamp'):
                    ts = item.timestamp
                    # 타임스탬프가 0이 아닌 유효한 값인지 확인
                    if ts > 0:
                        dbg_time = datetime.datetime.fromtimestamp(ts)
                        if dbg_time > datetime.datetime.now():
                            return 1 # 미래 시점
            return 0 # 정상 또는 디버그 정보 없음/타임스탬프 없음
        return -1 # 디버그 정보 없음
    except Exception as e:
        print(f"[WARN] Failed to check debug timestamp: {e}")
        return -1

def is_signed(filename: str) -> int:
    """signify 라이브러리를 사용하여 파일 서명 여부를 확인합니다."""
    try:
        with open(filename, "rb") as f:
            signed_pe = SignedPEFile(f)
            # verify() 메소드는 인증서 체인 검증까지 시도 (오래 걸릴 수 있음)
            # 여기서는 서명 존재 여부만 확인하는 것이 목적일 수 있음 (추후 확인 필요)
            # signed_pe.signed -> 서명 존재 여부 boolean 반환 가능성 있음 (라이브러리 문서 확인 필요)

            # 원본 코드 방식 유지 (verify 결과 사용)
            status, _ = signed_pe.explain_verify()
            # Verification Succeeded: 1 -> 서명됨(1)
            # Verification Failed: 2 -> 서명 안됨(0)
            # Other statuses -> 알수없음(-1)
            return {1: 1, 2: 0}.get(status.value, -1)
    except Exception as e:
        # signify 라이브러리가 특정 파일 형식 처리 못하거나 오류 발생 시
        print(f"[WARN] Failed to check signature for {os.path.basename(filename)}: {e}")
        return -1

def is_packed(filename: str) -> int:
    """YARA 룰을 사용하여 패킹 여부를 확인합니다."""
    if packer_rules is None:
        print("[WARN] Packer YARA rules not loaded. Skipping packing check.")
        return -1 # YARA 룰 로드 실패 시 -1 반환
    try:
        matches = packer_rules.match(filename)
        # 'IsPacked' 태그를 가진 룰이 매치되었는지 확인 (룰 파일 내용에 따라 수정 필요 가능성)
        return int(any(m.tags and 'IsPacked' in m.tags for m in matches))
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
        return "error"

# ====== 메인 특징 추출 함수 ======
def extract_features_for_file(input_file_path: str) -> Tuple[Dict[str, Any], str | None]:
    """
    주어진 단일 PE 파일 경로로부터 특징을 추출하고, 결과를 딕셔너리로 반환하며,
    동일 디렉토리에 CSV 파일로 저장합니다.

    Args:
        input_file_path (str): 분석할 PE 파일의 전체 경로.

    Returns:
        Tuple[Dict[str, Any], str | None]:
            - 첫 번째 요소: 추출된 특징들을 담은 딕셔너리. 오류 시 빈 딕셔너리 또는 오류 정보 포함.
            - 두 번째 요소: 저장된 CSV 파일의 경로. 저장 실패 시 None.
    """
    features: Dict[str, Any] = {}
    output_csv_path: str | None = None
    filename = os.path.basename(input_file_path) # 파일명만 추출

    try:
        print(f"[INFO] Processing: {filename}")

        # lief와 pefile 객체 생성 (오류 처리 강화)
        try:
            # lief.parse 는 파일이 없거나 PE 형식이 아니면 예외 발생 가능
            binary: lief.PE.Binary | None = lief.parse(input_file_path)
            if binary is None:
                 raise ValueError("Failed to parse file with lief (not a PE file or corrupted).")
        except lief.bad_file as e:
             raise ValueError(f"Lief bad_file error: {e}")
        except FileNotFoundError:
             raise FileNotFoundError(f"Input file not found: {input_file_path}")
        except Exception as e: # 기타 lief 파싱 오류
             raise ValueError(f"Error parsing with lief: {e}")

        try:
            pe = pefile.PE(input_file_path, fast_load=False)
        except pefile.PEFormatError as e:
            raise ValueError(f"pefile PEFormatError: {e}")
        except FileNotFoundError:
             raise FileNotFoundError(f"Input file not found: {input_file_path}")
        except Exception as e: # 기타 pefile 로딩 오류
            raise ValueError(f"Error loading with pefile: {e}")


        # --- 특징 추출 시작 ---
        features['filename'] = filename # 원본 파일명 추가
        features['sha256'] = calculate_sha256(input_file_path)
        features['isSigned'] = is_signed(input_file_path)
        features['isPacked'] = is_packed(input_file_path)

        # PE header features (pefile 사용)
        # Optional Header 접근 전 존재 여부 확인
        if hasattr(pe, 'OPTIONAL_HEADER'):
            features['MajorLinkerVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorLinkerVersion', 0)
            features['MinorLinkerVersion'] = getattr(pe.OPTIONAL_HEADER, 'MinorLinkerVersion', 0)
            features['SizeOfUninitializedData'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfUninitializedData', 0)
            features['ImageBase'] = getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0)
            features['FileAlignment'] = getattr(pe.OPTIONAL_HEADER, 'FileAlignment', 0)
            features['MajorOperatingSystemVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorOperatingSystemVersion', 0)
            features['MajorImageVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorImageVersion', 0)
            features['MinorImageVersion'] = getattr(pe.OPTIONAL_HEADER, 'MinorImageVersion', 0)
            features['MajorSubsystemVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorSubsystemVersion', 0)
            features['SizeOfImage'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', 0)
            features['SizeOfHeaders'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfHeaders', 0)
            features['CheckSum'] = getattr(pe.OPTIONAL_HEADER, 'CheckSum', 0)
            features['Subsystem'] = getattr(pe.OPTIONAL_HEADER, 'Subsystem', 0)
            features['DllCharacteristics'] = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
            features['SizeOfStackReserve'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfStackReserve', 0)
            features['SizeOfHeapReserve'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfHeapReserve', 0)
            # BaseOfData는 64비트 파일에 없을 수 있음
            features['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
        else:
            print(f"[WARN] Optional Header not found in {filename}")
            # 필수 헤더 필드 기본값 설정 또는 오류 처리

        # File Header 접근 전 존재 여부 확인
        if hasattr(pe, 'FILE_HEADER'):
            features['NumberOfSections'] = getattr(pe.FILE_HEADER, 'NumberOfSections', 0)
            features['Characteristics'] = getattr(pe.FILE_HEADER, 'Characteristics', 0)
        else:
            print(f"[WARN] File Header not found in {filename}")

        # DOS Header 접근 전 존재 여부 확인
        if hasattr(pe, 'DOS_HEADER'):
            features['e_cblp'] = getattr(pe.DOS_HEADER, 'e_cblp', 0)
            features['e_lfanew'] = getattr(pe.DOS_HEADER, 'e_lfanew', 0)
        else:
             print(f"[WARN] DOS Header not found in {filename}")

        # Section 정보 계산 (오류 처리 추가)
        try:
            features['SizeOfRawData'] = sum(s.SizeOfRawData for s in pe.sections) if hasattr(pe, 'sections') and pe.sections else 0
            features['Misc'] = sum(s.Misc_VirtualSize for s in pe.sections) if hasattr(pe, 'sections') and pe.sections else 0
        except Exception as e:
            print(f"[WARN] Error calculating section features for {filename}: {e}")
            features['SizeOfRawData'] = 0
            features['Misc'] = 0

        # Capabilities via YARA
        if capabilities_rules:
            try:
                matched = capabilities_rules.match(input_file_path)
                matched_names = [m.rule for m in matched]
                for cap in all_capabilities:
                    features[cap] = int(cap in matched_names)
            except Exception as e:
                print(f"[WARN] Failed to match capabilities rules for {filename}: {e}")
                # 모든 capability를 0 또는 -1로 설정
                for cap in all_capabilities:
                    features[cap] = -1 # 오류 발생 의미
        else:
             print("[WARN] Capabilities YARA rules not loaded. Skipping capabilities check.")
             for cap in all_capabilities:
                 features[cap] = -1 # YARA 룰 로드 실패 의미

        # 추가 분석 플래그 (lief 사용)
        features['has_manifest'] = has_manifest(binary)
        features['has_aslr'] = has_aslr(binary)
        features['has_tls'] = has_tls(binary)
        features['has_dep'] = has_dep(binary)
        features['code_integrity'] = check_ci(binary)
        features['supports_cfg'] = supports_cfg(binary)
        features['suspicious_dbgts'] = suspicious_dbgts(binary)

        pe.close() # pefile 객체 닫기

        # --- 특징 추출 완료 ---

        # --- CSV 파일 저장 ---
        # 출력 파일 경로 생성 (입력 파일과 같은 디렉토리, 이름 뒤에 _features.csv 추가)
        output_dir = os.path.dirname(input_file_path)
        base_filename = os.path.basename(input_file_path)
        output_csv_filename = f"{base_filename}_features.csv"
        output_csv_path = os.path.join(output_dir, output_csv_filename)

        # DataFrame 생성 (단일 행)
        # features 딕셔너리를 리스트 안에 넣어 DataFrame 생성
        df = pd.DataFrame([features])

        # CSV 저장
        df.to_csv(output_csv_path, index=False)
        print(f"[INFO] Features saved to: {output_csv_path}")

    except (ValueError, FileNotFoundError) as e: # 파일 파싱/읽기 오류
        print(f"[ERROR] Error processing {filename}: {e}")
        features['error'] = str(e) # 오류 정보 추가
        # 이 경우 CSV는 저장되지 않음
    except Exception as e: # 기타 예외 처리
        print(f"[ERROR] Unexpected error processing {filename}: {e}")
        features['error'] = str(e)
        # 이 경우 CSV는 저장되지 않음
    finally:
        # pe 객체가 성공적으로 생성되었을 경우 close 호출 (이미 try 블록 안에 있음)
        pass

    return features, output_csv_path # 특징 딕셔너리와 CSV 경로 반환