# analysis.py

import time
from typing import Dict, Any

# 수정된 특징 추출 함수 임포트
from file_to_features import extract_features_for_file

# run_analysis 함수를 동기 함수로 변경 (특징 추출이 동기 작업이므로)
def run_analysis(file_path: str) -> Dict[str, Any]:
    """
    주어진 파일 경로에 대해 특징 추출을 수행하고,
    분석 결과를 딕셔너리로 반환합니다.
    Args:
        file_path (str): 분석할 파일의 전체 경로

    Returns:
        Dict[str, Any]: 분석 결과 ('success', 'message', 'is_malicious' 포함)
    """
    print(f"[INFO] Analysis process started for: {file_path}")
    start_time = time.time() # 시작 시간 기록

    # 최종 반환될 변수들 초기화
    success: bool = False
    message: str = ""
    is_malicious: bool | None = None # AI 예측 결과 초기화

    # --- 특징 추출 로직 시작 ---
    try:
        # file_to_features.py의 함수 호출하여 특징 추출 및 CSV 저장 시도
        features_dict, csv_path = extract_features_for_file(file_path)

        # 특징 추출 성공 여부 확인 후, 성공 메세지 출력
        if csv_path and 'error' not in features_dict:
            print(f"[INFO] Feature extraction successful for: {file_path}. CSV saved at {csv_path}")
            success = True
            message = f"특징 추출 성공. (CSV: {csv_path})"
            is_malicious = None     # AI 예측 결과는 현재 없으므로 None으로 설정

        else:
            # 특징 추출 자체에서 실패한 경우
            error_msg = features_dict.get('error', "특징 추출 중 알 수 없는 오류 발생")
            print(f"[ERROR] Feature extraction failed for {file_path}: {error_msg}")
            success = False
            message = f"특징 추출 실패: {error_msg}"
            is_malicious = None

    except Exception as e:
        # 예기치 못한 오류 발생 시 (모듈 임포트 실패 등)
        # FileNotFoundError도 그냥 여기에 한번에 처리해버리도록 합쳤어요 코드만 더 길어져보이길래
        print(f"[ERROR] Unexpected error during analysis process for {file_path}: {e}")
        success = False
        message = f"분석 프로세스 중 예외 발생: {e}"
        is_malicious = None
    # --- 특징 추출 로직 끝 ---

    # 나중에 아래 코드 변형해서 final_result에 포함시켜서 웹페이지에도 소모된 시간 출력해도될것같아요
    end_time = time.time()
    analysis_time = round(end_time - start_time, 3)
    print(f"[INFO] Analysis process finished for: {file_path}. Time taken: {analysis_time}s")

    # 최종적으로 라우터에 전달할 결과 딕셔너리 구성
    final_result = {
        "success": success,
        "message": message,
        "is_malicious": is_malicious, # 현재는 항상 None / 모델 합쳐지면 그때 수정 필요
    }

    return final_result
