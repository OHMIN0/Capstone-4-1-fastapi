# file_to_features.py

import os
import time
import pandas as pd
import datetime
import hashlib
import pefile
import lief
import yara # yara ?엫?룷?듃?뒗 ?쑀吏?
from signify.authenticode import SignedPEFile
from typing import Dict, Any, List, Tuple
from functools import lru_cache # 媛꾨떒?븳 罹먯떛?쓣 ?쐞?빐 異붽??

# ====== ?꽕?젙 (YARA 猷? 寃쎈줈) ======
YARA_RULES_DIR = "yara_rules"
CAPABILITIES_RULES_FILE = os.path.join(YARA_RULES_DIR, 'capabilities.yar')
PACKER_RULES_FILE = os.path.join(YARA_RULES_DIR, 'packer_compiler_signatures.yar')

# ====== YARA 猷? 而댄뙆?씪 ?븿?닔 (罹먯떛 ?궗?슜) ======
# ?룞?씪?븳 ?뙆?씪?쓣 諛섎났?빐?꽌 而댄뙆?씪?븯?뒗 寃껋쓣 諛⑹???븯湲? ?쐞?빐 LRU 罹먯떆 ?궗?슜
@lru_cache(maxsize=2) # 理쒕?? 2媛? 猷곗뀑 罹먯떛 (capabilities, packer)
def compile_yara_rules(filepath: str):
    """二쇱뼱吏? 寃쎈줈?쓽 YARA 猷곗쓣 而댄뙆?씪?빀?땲?떎. ?떎?뙣 ?떆 None 諛섑솚 諛? 寃쎄퀬 異쒕젰."""
    try:
        # Dockerfile?뿉?꽌 yara_rules ?뤃?뜑瑜? 蹂듭궗?뻽?뒗吏? ?솗?씤 ?븘?슂
        if not os.path.exists(filepath):
            print(f"[WARN] YARA rule file not found: {filepath}. Rule matching will be skipped.")
            return None
        compiled_rules = yara.compile(filepath=filepath)
        print(f"[INFO] YARA rule compiled successfully: {filepath}")
        return compiled_rules
    except Exception as e:
        print(f"[ERROR] Failed to compile YARA rule {filepath}: {e}")
        return None

# ====== Capabilities ?젙?쓽 ======
# (?궗?슜?옄媛? ?젣怨듯븳 由ъ뒪?듃)
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

# ====== ?듅吏? 異붿텧 ?뿬?띁 ?븿?닔?뱾 (?븞?젙?꽦 媛쒖꽑) ======
# (?씠?쟾 '媛쒖꽑?맖' 踰꾩쟾?쓽 ?븿?닔?뱾 ?궗?슜)
def get_characteristics_list(binary: lief.PE.Binary) -> List[str]:
    """lief 諛붿씠?꼫由? 媛앹껜?뿉?꽌 DLL ?듅?꽦 由ъ뒪?듃瑜? 臾몄옄?뿴濡? 諛섑솚?빀?땲?떎."""
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
    """由ъ냼?뒪 留ㅻ땲?????? 留ㅻ땲?럹?뒪?듃 議댁옱 ?뿬遺?瑜? 諛섑솚?빀?땲?떎."""
    try:
        return int(binary and binary.has_resources and hasattr(binary, 'resources_manager') and binary.resources_manager.has_manifest)
    except Exception as e:
        print(f"[WARN] Failed to check manifest: {e}")
        return -1

def has_aslr(binary: lief.PE.Binary) -> int:
    """ASLR 吏??썝 ?뿬遺?瑜? 諛섑솚?빀?땲?떎."""
    return int("DYNAMIC_BASE" in get_characteristics_list(binary))

def has_tls(binary: lief.PE.Binary) -> int:
    """TLS ?궗?슜 ?뿬遺?瑜? 諛섑솚?빀?땲?떎."""
    try:
        return int(binary and binary.has_tls)
    except Exception as e:
        print(f"[WARN] Failed to check TLS: {e}")
        return -1

def has_dep(binary: lief.PE.Binary) -> int:
    """DEP 吏??썝 ?뿬遺?瑜? 諛섑솚?빀?땲?떎."""
    return int("NX_COMPAT" in get_characteristics_list(binary))

def check_ci(binary: lief.PE.Binary) -> int:
    """Code Integrity ?솗?씤."""
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
    """Control Flow Guard 吏??썝 ?뿬遺?瑜? 諛섑솚?빀?땲?떎."""
    return int("GUARD_CF" in get_characteristics_list(binary))

def suspicious_dbgts(binary: lief.PE.Binary) -> int:
    """?뵒踰꾧렇 ????엫?뒪?꺃?봽媛? 誘몃옒 ?떆?젏?씤吏? ?솗?씤?빀?땲?떎."""
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
    """signify ?씪?씠釉뚮윭由щ?? ?궗?슜?븯?뿬 ?뙆?씪 ?꽌紐? ?뿬遺?瑜? ?솗?씤?빀?땲?떎."""
    try:
        with open(filename, "rb") as f:
            signed_pe = SignedPEFile(f)
            return 1 if signed_pe.signed else 0
    except Exception as e:
        print(f"[WARN] Failed to check signature for {os.path.basename(filename)}: {e}")
        return -1

def is_packed(filename: str) -> int:
    """YARA 猷곗쓣 ?궗?슜?븯?뿬 ?뙣?궧 ?뿬遺?瑜? ?솗?씤?빀?땲?떎 (?궡遺??뿉?꽌 猷? 而댄뙆?씪)."""
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
    """?뙆?씪?쓽 SHA256 ?빐?떆瑜? 怨꾩궛?빀?땲?떎."""
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to calculate SHA256 for {os.path.basename(filename)}: {e}")
        return "error_calculating_hash"

# ====== 硫붿씤 ?듅吏? 異붿텧 諛? ????옣 ?븿?닔 ======
def extract_features_for_file(input_file_path: str) -> Tuple[Dict[str, Any], str | None]:
    """
    二쇱뼱吏? ?떒?씪 PE ?뙆?씪 寃쎈줈濡쒕???꽣 ?듅吏뺤쓣 異붿텧?븯怨?, 寃곌낵瑜? ?뵓?뀛?꼫由щ줈 諛섑솚?븯硫?,
    ?룞?씪 ?뵒?젆?넗由ъ뿉 CSV ?뙆?씪濡? ????옣?빀?땲?떎. (吏??젙?맂 ?뿴 ?닚?꽌 ?쟻?슜)
    """
    features: Dict[str, Any] = {}
    output_csv_path: str | None = None
    filename = os.path.basename(input_file_path)
    start_time = time.time() # ?븿?닔 ?떆?옉 ?떆媛? 湲곕줉

    # Capabilities 猷? 而댄뙆?씪 ?떆?룄 (?븿?닔 ?샇異? ?떆)
    capabilities_rules = compile_yara_rules(CAPABILITIES_RULES_FILE)

    try:
        print(f"[INFO] Processing: {filename}")
        binary: lief.PE.Binary | None = None # lief 媛앹껜 珥덇린?솕
        pe: pefile.PE | None = None # pefile 媛앹껜 珥덇린?솕

        # lief??? pefile 媛앹껜 ?깮?꽦 ?떆?룄 (?삤瑜? 諛쒖깮 ?떆?뿉?룄 ?듅吏? 異붿텧 怨꾩냽 ?떆?룄)
        try:
            binary = lief.parse(input_file_path)
            if binary is None:
                 print(f"[WARN] Lief parse failed for {filename}.")
        except lief.bad_file as e:
             print(f"[WARN] Lief bad_file error for {filename}: {e}")
        except FileNotFoundError:
             print(f"[ERROR] Input file not found for lief: {input_file_path}")
             raise # ?뙆?씪 ?뾾?쓬??? 怨꾩냽 吏꾪뻾 遺덇??
        except Exception as e:
             print(f"[WARN] Error parsing with lief for {filename}: {e}")

        try:
            pe = pefile.PE(input_file_path, fast_load=False)
        except pefile.PEFormatError as e:
            print(f"[WARN] pefile PEFormatError for {filename}: {e}")
        except FileNotFoundError:
             print(f"[ERROR] Input file not found for pefile: {input_file_path}")
             raise # ?뙆?씪 ?뾾?쓬??? 怨꾩냽 吏꾪뻾 遺덇??
        except Exception as e:
            print(f"[WARN] Error loading with pefile for {filename}: {e}")

        # --- ?듅吏? 異붿텧 ?떆?옉 ---
        features['filename'] = filename
        features['sha256'] = calculate_sha256(input_file_path)
        features['isSigned'] = is_signed(input_file_path)
        features['isPacked'] = is_packed(input_file_path) # ?븿?닔 ?궡遺??뿉?꽌 packer 猷? 而댄뙆?씪

        # PE header features (pefile ?궗?슜)
        if pe and hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
            opt_header = pe.OPTIONAL_HEADER
            features['MajorLinkerVersion'] = getattr(opt_header, 'MajorLinkerVersion', 0)
            features['MinorLinkerVersion'] = getattr(opt_header, 'MinorLinkerVersion', 0)
            # ... (湲고?? Optional Header ?븘?뱶) ...
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

        # Capabilities via YARA (而댄뙆?씪?맂 猷? 媛앹껜 ?궗?슜)
        if capabilities_rules: # 猷? 而댄뙆?씪 ?꽦怨? ?떆?뿉留? ?떎?뻾
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

        # 異붽?? 遺꾩꽍 ?뵆?옒洹? (lief ?궗?슜, binary 媛앹껜 None 泥댄겕 異붽??)
        if binary:
            features['has_manifest'] = has_manifest(binary)
            features['has_aslr'] = has_aslr(binary)
            features['has_tls'] = has_tls(binary)
            features['has_dep'] = has_dep(binary)
            features['code_integrity'] = check_ci(binary)
            features['supports_cfg'] = supports_cfg(binary)
            features['suspicious_dbgts'] = suspicious_dbgts(binary)
        else:
            # lief ?뙆?떛 ?떎?뙣 ?떆 湲곕낯媛? -1 ?꽕?젙
            lief_flags = ['has_manifest', 'has_aslr', 'has_tls', 'has_dep', 'code_integrity', 'supports_cfg', 'suspicious_dbgts']
            for flag in lief_flags: features.setdefault(flag, -1)

        # --- ?듅吏? 異붿텧 ?셿猷? ---

        # --- CSV ?뙆?씪 ????옣 (吏??젙?맂 ?뿴 ?닚?꽌 ?쟻?슜) ---
        output_dir = os.path.dirname(input_file_path)
        output_csv_filename = f"{filename}_features.csv"
        output_csv_path = os.path.join(output_dir, output_csv_filename)

        # CSV ????옣 ?쐞?븳 ?뿴 ?닚?꽌 ?젙?쓽
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
            output_csv_path = None # ????옣 ?떎?뙣

    except (ValueError, FileNotFoundError) as e: # ?뙆?씪 ?뾾?쓬 ?삉?뒗 ?뙆?떛 遺덇?? ?삤瑜?
        print(f"[ERROR] Cannot process file {filename}: {e}")
        features['error'] = str(e) # ?삤瑜? ?젙蹂? 異붽??
    except Exception as e: # 湲고?? ?삁?쇅 泥섎━
        print(f"[ERROR] Unexpected error processing {filename}: {e}")
        features['error'] = str(e)
    finally:
        # pefile 媛앹껜 ?떕湲? (?깮?꽦 ?꽦怨? ?떆)
        if 'pe' in locals() and pe and hasattr(pe, 'close'):
            try: pe.close()
            except Exception as close_e: print(f"[WARN] Error closing pefile object: {close_e}")

    # 泥섎━ ?떆媛꾩?? CSV ????옣 ?썑 features ?뵓?뀛?꼫由ъ뿉 異붽??
    end_time = time.time()
    features['processing_time'] = round(end_time - start_time, 3)

    # 理쒖쥌?쟻?쑝濡? ?듅吏? ?뵓?뀛?꼫由ъ?? CSV 寃쎈줈 諛섑솚
    return features, output_csv_path
