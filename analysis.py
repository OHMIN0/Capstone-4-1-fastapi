# analysis.py

import time
import os
from typing import Dict, Any, List
import joblib # 모델 및 객체 로드를 위해 추가
import pandas as pd # 데이터프레임 사용을 위해 추가
import numpy as np # 모델 입력을 위해 추가
import lightgbm

# 수정된 특징 추출 함수 임포트
from file_to_features import extract_features_for_file # suspicious_dbgts 포함된 버전 사용

# --- AI 모델 및 관련 객체 로딩 ---
MODEL_DIR = 'models' # 모델 파일이 저장된 디렉토리 (프로젝트 루트 기준)
MODEL_FILENAME = 'lightgbm_static_model.joblib'
FEATURE_COLUMNS_FILENAME = 'feature_columns.joblib' # 학습 시 사용된 특징 리스트 파일명

MODEL_PATH = os.path.join(MODEL_DIR, MODEL_FILENAME)
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, FEATURE_COLUMNS_FILENAME)

model = None
FEATURE_COLUMNS = None # 학습에 사용된 특징 이름 리스트

try:
    # 모델 로드
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"[INFO] AI Model Loaded Successful: {MODEL_PATH}")
    else:
        print(f"[ERROR] AI Model File Not Found: {MODEL_PATH}. Prediction feature will be disabled.")

    # 학습 시 사용된 특징 컬럼 리스트 로드
    if os.path.exists(FEATURE_COLUMNS_PATH):
        FEATURE_COLUMNS = joblib.load(FEATURE_COLUMNS_PATH)
        if FEATURE_COLUMNS and isinstance(FEATURE_COLUMNS, list):
            print(f"[INFO] Feature columns list loaded successfully. Number of columns: {len(FEATURE_COLUMNS)}")
        else:
            print(f"[WARN] Feature columns list file is empty or invalid: {FEATURE_COLUMNS_PATH}")
            model = None # 특징 정보 없으면 모델 사용 불가
    else:
        print(f"[ERROR] Feature columns list file not found: {FEATURE_COLUMNS_PATH}. Prediction feature will be disabled.")
        model = None # 특징 정보 없으면 모델 사용 불가

except Exception as load_e:
    print(f"[ERROR] Error during model or related object loading: {load_e}")
    model = None # 로딩 실패 시 모델 사용 불가

# --- 특징 전처리 함수 ---
def preprocess_features_for_model(features_dict: Dict[str, Any], trained_feature_columns: List[str]) -> pd.DataFrame | None:
    """
    추출된 특징 딕셔너리를 AI 모델 입력 형식(Pandas DataFrame)으로 변환합니다.
    학습 시 사용된 특징만 선택하고 순서를 맞춥니다.
    """
    if not trained_feature_columns:
        print("[ERROR] Trained feature column information not available. Preprocessing cannot be performed.")
        return None
    try:
        # 모델 학습에 사용된 특징만, 학습 시 순서대로 선택/정렬
        model_input_data = {}
        for col in trained_feature_columns:
            value = features_dict.get(col, 0) # 학습 시 사용된 특징이 없으면 0으로 채움
            try:
                model_input_data[col] = float(value)
            except (ValueError, TypeError):
                print(f"[WARN] During preprocessing, value '{value}' for feature '{col}' could not be converted to float, using 0.0.")
                model_input_data[col] = 0.0
        
        model_input_df = pd.DataFrame([model_input_data], columns=trained_feature_columns)
        
        return model_input_df

    except Exception as e:
        print(f"[ERROR] Error during feature preprocessing: {e}")
        return None

# run_analysis 함수
def run_analysis(file_path: str) -> Dict[str, Any]:
    """
    주어진 파일 경로에 대해 특징 추출 및 AI 모델 예측을 수행하고 결과를 반환합니다.
    """
    print(f"[INFO] Analysis process started for: {file_path}")
    start_time = time.time()

    success: bool = False
    message: str = ""
    is_malicious: bool | None = None # AI 예측 결과 (악성이면 True, 정상이면 False)
    confidence: float | None = None # 정확도(확신도) 변수 추가

    try:
        # 1. 특징 추출
        features_dict, csv_path = extract_features_for_file(file_path) 

        if csv_path and 'error' not in features_dict:
            print(f"[INFO] Feature extraction successful. CSV: {csv_path}")

            # 2. AI 모델 예측 (모델과 특징 컬럼 정보가 로드된 경우)
            if model and FEATURE_COLUMNS:
                try:
                    # 특징 전처리
                    model_input_df = preprocess_features_for_model(features_dict, FEATURE_COLUMNS)

                    if model_input_df is not None and not model_input_df.empty:
                        # 예측 수행
                        prediction = model.predict(model_input_df)
                        is_malicious = bool(prediction[0] == 1) # 모델 출력이 1이면 악성으로 가정

                        # 모델 확신도(정확도) 확률
                        if hasattr(model, "predict_proba"):
                            probabilities = model.predict_proba(model_input_df)
                           
                            if is_malicious:
                                confidence = float(probabilities[0][1]) # Probability of being malicious
                            else:
                                confidence = float(probabilities[0][0]) # Probability of being normal
                            
                            message = f"특징 추출 및 AI 분석 완료. 예측 결과: {'악성 파일 의심' if is_malicious else '정상 파일로 판단됨'} (신뢰도: {confidence:.2%})"
                        else:
                            # Fallback if predict_proba is not available
                            message = f"특징 추출 및 AI 분석 완료. 예측 결과: {'악성 파일 의심' if is_malicious else '정상 파일로 판단됨'} (신뢰도 확인 불가)"
                        success = True

                    else:
                        message = "특징 추출은 성공했으나, AI 입력을 위한 전처리 중 오류 발생."
                        is_malicious = None
                        success = False 

                except Exception as model_e:
                    print(f"[ERROR] AI prediction step failed for {file_path}: {model_e}")
                    success = False
                    message = f"특징 추출은 성공했으나 AI 예측 중 오류 발생: {model_e}"
                    is_malicious = None
            else:
                message = "특징 추출 성공. AI 모델 또는 특징 정보가 로드되지 않아 예측을 수행할 수 없습니다."
                is_malicious = None # 모델 없으면 예측 불가
                success = True # 특징 추출까지는 성공으로 간주

        else:
            error_msg = features_dict.get('error', "특징 추출 중 알 수 없는 오류 발생")
            print(f"[ERROR] Feature extraction failed for {file_path}: {error_msg}")
            success = False
            message = f"특징 추출 실패: {error_msg}"
            is_malicious = None

    except FileNotFoundError as e:
         print(f"[ERROR] File not found during analysis process for {file_path}: {e}")
         success = False
         message = f"분석할 파일을 찾을 수 없습니다: {e}"
         is_malicious = None
    except Exception as e:
        print(f"[ERROR] Unexpected error during analysis process for {file_path}: {e}")
        success = False
        message = f"분석 프로세스 중 예외 발생: {e}"
        is_malicious = None

    end_time = time.time()
    analysis_time = round(end_time - start_time, 3)
    print(f"[INFO] Analysis process finished for: {file_path}. Time taken: {analysis_time}s")

    final_result = {
        "success": success,
        "message": message,
        "is_malicious": is_malicious,
        "confidence": confidence
    }
    return final_result
