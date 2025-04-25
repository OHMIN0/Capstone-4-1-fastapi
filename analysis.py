# analysis.py

import time
from typing import Dict, Any

# �닔�젙�맂 �듅吏� 異붿텧 �븿�닔 �엫�룷�듃 
from file_to_features import extract_features_for_file 

# --- �떎�젣 AI 紐⑤뜽 濡쒕뵫 遺�遺� (�굹以묒뿉 異붽��) ---
# �삁: import joblib
# model = joblib.load(config.MODEL_PATH)


# run_analysis �븿�닔瑜� �룞湲� �븿�닔濡� 蹂�寃� (�듅吏� 異붿텧�씠 �룞湲� �옉�뾽�씠誘�濡�)
def run_analysis(file_path: str) -> Dict[str, Any]:
    """
    二쇱뼱吏� �뙆�씪 寃쎈줈�뿉 ����빐 �듅吏� 異붿텧�쓣 �닔�뻾�븯怨� 寃곌낵瑜� �뵓�뀛�꼫由щ줈 諛섑솚�빀�땲�떎.
    (�쁽�옱�뒗 AI 紐⑤뜽 �삁痢≪�� �닔�뻾�븯吏� �븡�쓬)

    Args:
        file_path (str): 遺꾩꽍�븷 �뙆�씪�쓽 �쟾泥� 寃쎈줈

    Returns:
        Dict[str, Any]: �듅吏� 異붿텧 寃곌낵 諛� 愿��젴 �젙蹂대�� �떞��� �뵓�뀛�꼫由�
    """
    print(f"[INFO] Analysis process started for: {file_path}")
    start_time = time.time()
    analysis_result: Dict[str, Any] = {} # 理쒖쥌 諛섑솚�맆 �뵓�뀛�꼫由�

    # --- �듅吏� 異붿텧 濡쒖쭅 �떆�옉 ---
    try:
        # file_to_features.py�쓽 �븿�닔 �샇異쒗븯�뿬 �듅吏� 異붿텧 諛� CSV ����옣 �떆�룄
        # �씠 �븿�닔�뒗 �듅吏� �뵓�뀛�꼫由ъ�� ����옣�맂 CSV 寃쎈줈(�꽦怨� �떆) �삉�뒗 None(�떎�뙣 �떆)�쓣 諛섑솚
        features_dict, csv_path = extract_features_for_file(file_path)

        # �듅吏� 異붿텧 �꽦怨� �뿬遺� �솗�씤 (諛섑솚�맂 csv_path 議댁옱 �뿬遺� 諛� features_dict �궡 'error' �궎 遺��옱 �솗�씤)
        if csv_path and 'error' not in features_dict:
            print(f"[INFO] Feature extraction successful for: {file_path}")
            success = True
            message = f"�듅吏� 異붿텧 諛� CSV ����옣 �꽦怨�: {csv_path}"
            # �븘�슂 �떆 異붿텧�맂 �듅吏� �옄泥대�� 寃곌낵�뿉 �룷�븿 媛��뒫
            # analysis_result['extracted_features'] = features_dict
        else:
            # �듅吏� 異붿텧 �떎�뙣 �삉�뒗 �뙆�씪 泥섎━ �삤瑜� �떆
            error_msg = features_dict.get('error', "�듅吏� 異붿텧 以� �븣 �닔 �뾾�뒗 �삤瑜� 諛쒖깮")
            print(f"[ERROR] Feature extraction failed for {file_path}: {error_msg}")
            success = False
            message = f"�듅吏� 異붿텧 �떎�뙣: {error_msg}"
            # �떎�뙣 �떆 csv_path�뒗 None�씪 寃껋엫

        # --- AI 紐⑤뜽 �삁痢� 濡쒖쭅 (�굹以묒뿉 異붽���맆 �쐞移�) ---
        # �쁽�옱�뒗 AI �삁痢� 寃곌낵�뒗 �뾾�쑝誘�濡� None�쑝濡� �꽕�젙
        is_malicious = None
        confidence = None
        # 留뚯빟 �굹以묒뿉 AI �삁痢� 異붽�� �떆, message �뿉 �삁痢� 寃곌낵 �삉�뒗 �긽�깭 異붽�� 媛��뒫
        # if success: message += " (AI Prediction Pending)"

    except Exception as e:
        # extract_features_for_file �븿�닔 �샇異� �옄泥댁뿉�꽌 �삁�쇅 諛쒖깮 �떆
        # (�삁: file_to_features 紐⑤뱢 �엫�룷�듃 �떎�뙣, 寃쎈줈 臾몄젣 �벑 �떖媛곹븳 �삤瑜�)
        print(f"[ERROR] Unexpected error during analysis process for {file_path}: {e}")
        success = False
        message = f"遺꾩꽍 �봽濡쒖꽭�뒪 以� �삁�쇅 諛쒖깮: {e}"
        is_malicious = None
        confidence = None
        csv_path = None # �삁�쇅 諛쒖깮 �떆 CSV 寃쎈줈 �뾾�쓬
    # --- �듅吏� 異붿텧 濡쒖쭅 �걹 ---

    end_time = time.time()
    analysis_time = round(end_time - start_time, 3) # �듅吏� 異붿텧�뿉 �냼�슂�맂 �떆媛�

    # 理쒖쥌 寃곌낵 �뵓�뀛�꼫由� 援ъ꽦
    analysis_result.update({
        "file_path": file_path,           # �썝蹂� �뙆�씪 寃쎈줈
        "csv_path": csv_path,             # ����옣�맂 CSV 寃쎈줈 (�꽦怨� �떆 寃쎈줈, �떎�뙣 �떆 None)
        "analysis_time": analysis_time,   # 遺꾩꽍(�듅吏� 異붿텧) �냼�슂 �떆媛�
        "message": message,               # 泥섎━ 寃곌낵 硫붿떆吏�
        "success": success,               # �듅吏� 異붿텧 �꽦怨� �뿬遺�
        "is_malicious": is_malicious,     # AI �삁痢� 寃곌낵 (�쁽�옱 None)
        "confidence": confidence          # AI �삁痢� �떊猶곕룄 (�쁽�옱 None)
    })

    print(f"[INFO] Analysis process finished for: {file_path}")
    return analysis_result

# --- �븘�슂 �떆 PE �뙆�씪 �듅吏� �쟾泥섎━ �벑�쓽 蹂댁“ �븿�닔瑜� �뿬湲곗뿉 異붽�� ---
# def preprocess_features(features_dict):
#    # ... �듅吏� �뵓�뀛�꼫由щ�� 紐⑤뜽 �엯�젰 �삎�깭濡� 蹂��솚 ...
#    return model_input
