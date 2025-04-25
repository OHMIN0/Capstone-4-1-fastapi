# analysis.py

import time
from typing import Dict, Any

# 수정된 특징 추출 함수 임포트
from file_to_features import extract_features_for_file

# --- 실제 AI 모델 로딩 부분 (나중에 추가) ---
# 예: import joblib
# model = joblib.load(config.MODEL_PATH)


# run_analysis 함수를 동기 함수로 변경 (특징 추출이 동기 작업이므로)
def run_analysis(file_path: str) -> Dict[str, Any]:
    """
    주어진 파일 경로에 대해 특징 추출을 수행하고 결과를 딕셔너리로 반환합니다.
    (현재는 AI 모델 예측은 수행하지 않음)

    Args:
        file_path (str): 분석할 파일의 전체 경로

    Returns:
        Dict[str, Any]: 특징 추출 결과 및 관련 정보를 담은 딕셔너리
    """
    print(f"[INFO] Analysis process started for: {file_path}")
    start_time = time.time()
    analysis_result: Dict[str, Any] = {} # 최종 반환될 딕셔너리

    # --- 특징 추출 로직 시작 ---
    try:
        # file_to_features.py의 함수 호출하여 특징 추출 및 CSV 저장 시도
        # 이 함수는 특징 딕셔너리와 저장된 CSV 경로(성공 시) 또는 None(실패 시)을 반환
        features_dict, csv_path = extract_features_for_file(file_path)

        # 특징 추출 성공 여부 확인 (반환된 csv_path 존재 여부 및 features_dict 내 'error' 키 부재 확인)
        if csv_path and 'error' not in features_dict:
            print(f"[INFO] Feature extraction successful for: {file_path}")
            success = True
            message = f"특징 추출 및 CSV 저장 성공: {csv_path}"
            # 필요 시 추출된 특징 자체를 결과에 포함 가능
            # analysis_result['extracted_features'] = features_dict
        else:
            # 특징 추출 실패 또는 파일 처리 오류 시
            error_msg = features_dict.get('error', "특징 추출 중 알 수 없는 오류 발생")
            print(f"[ERROR] Feature extraction failed for {file_path}: {error_msg}")
            success = False
            message = f"특징 추출 실패: {error_msg}"
            # 실패 시 csv_path는 None일 것임

        # --- AI 모델 예측 로직 (나중에 추가될 위치) ---
        # 현재는 AI 예측 결과는 없으므로 None으로 설정
        is_malicious = None
        confidence = None
        # 만약 나중에 AI 예측 추가 시, message 에 예측 결과 또는 상태 추가 가능
        # if success: message += " (AI Prediction Pending)"

    except Exception as e:
        # extract_features_for_file 함수 호출 자체에서 예외 발생 시
        # (예: file_to_features 모듈 임포트 실패, 경로 문제 등 심각한 오류)
        print(f"[ERROR] Unexpected error during analysis process for {file_path}: {e}")
        success = False
        message = f"분석 프로세스 중 예외 발생: {e}"
        is_malicious = None
        confidence = None
        csv_path = None # 예외 발생 시 CSV 경로 없음
    # --- 특징 추출 로직 끝 ---

    end_time = time.time()
    analysis_time = round(end_time - start_time, 3) # 특징 추출에 소요된 시간

    # 최종 결과 딕셔너리 구성
    analysis_result.update({
        "file_path": file_path,           # 원본 파일 경로
        "csv_path": csv_path,             # 저장된 CSV 경로 (성공 시 경로, 실패 시 None)
        "analysis_time": analysis_time,   # 분석(특징 추출) 소요 시간
        "message": message,               # 처리 결과 메시지
        "success": success,               # 특징 추출 성공 여부
        "is_malicious": is_malicious,     # AI 예측 결과 (현재 None)
        "confidence": confidence          # AI 예측 신뢰도 (현재 None)
    })

    print(f"[INFO] Analysis process finished for: {file_path}")
    return analysis_result

# --- 필요 시 PE 파일 특징 전처리 등의 보조 함수를 여기에 추가 ---
# def preprocess_features(features_dict):
#    # ... 특징 딕셔너리를 모델 입력 형태로 변환 ...
#    return model_input
