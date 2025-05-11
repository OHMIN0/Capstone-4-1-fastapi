# train_model.py

## 모델과 프로젝트 안정적 결합을 위한 특징추출 코드.
## 추후 다시 쓰일 일이 있을 수도 있어, 일단 keeping폴더를 새로 만들어 따로 보관할 예정.
## features.csv파일도 동일.


import pandas as pd
# import lightgbm as lgb # 모델 학습 생략으로 주석 처리
from sklearn.model_selection import train_test_split # 데이터 분할에는 여전히 사용될 수 있으나, 실제 학습 안 하므로 선택적
# from sklearn.metrics import classification_report, confusion_matrix, accuracy_score # 모델 평가 생략으로 주석 처리
import joblib
import os
import numpy as np

# --- 설정 ---
CSV_FILE_PATH = 'static_modified.csv' # 원본 특징 데이터 CSV 파일 경로 (사용자가 업로드한 파일)
MODEL_SAVE_DIR = 'models'      # 관련 객체를 저장할 디렉토리
# MODEL_FILENAME = 'lightgbm_static_model.joblib' # 모델 저장 생략
FEATURE_COLUMNS_FILENAME = 'feature_columns.joblib' # 학습에 사용될 특징 리스트 파일명

# NUM_SAMPLES = 100 # 샘플링 관련 설정은 유지 (X 데이터 구성을 위해)
TEST_SIZE = 0.2
RANDOM_STATE = 42

# --- 모델 저장 디렉토리 생성 ---
os.makedirs(MODEL_SAVE_DIR, exist_ok=True)

# --- 1. 데이터 로드 ---
try:
    df_full = pd.read_csv(CSV_FILE_PATH)
    print(f"CSV 파일 로드 성공: {CSV_FILE_PATH}, 총 샘플 수: {len(df_full)}")
except FileNotFoundError:
    print(f"[ERROR] CSV 파일을 찾을 수 없습니다: {CSV_FILE_PATH}")
    exit()
except Exception as e:
    print(f"[ERROR] CSV 파일 로드 중 오류 발생: {e}")
    exit()

# --- 원본 DataFrame에서 family를 label로 변환 및 불필요 컬럼 제거 ---
df = df_full.copy()

if "filename" in df.columns:
    df = df.drop(columns=["filename"])
if "sha256" in df.columns:
    df = df.drop(columns=["sha256"])
if "id" in df.columns:
    df = df.drop(columns=["id"])

if 'family' in df.columns:
    df['label'] = df['family'].apply(lambda x: 0 if x == 0 else 1)
    print("'family' 컬럼을 기반으로 'label' 생성 완료.")
else:
    print("[ERROR] 'family' 컬럼이 원본 CSV에 없습니다. 라벨 생성이 불가합니다.")
    if 'label' not in df.columns:
        print("[WARN] 'label' 컬럼도 없어 임시 랜덤 라벨을 생성합니다. 실제 학습에는 정확한 라벨이 필요합니다.")
        df['label'] = np.random.randint(0, 2, size=len(df))
    # exit()

# --- (선택 사항) 데이터 샘플링 ---
# NUM_SAMPLES 변수가 정의되어 있다면 샘플링 로직은 유지하여 X 구성을 확인
# 현재는 전체 데이터 사용으로 주석 처리되어 있음
sampled_df = df
print(f"전체 데이터 ({len(sampled_df)}개)를 특징 리스트 추출에 사용합니다.")


# --- 3. 특징(X) 및 라벨(y) 분리 ---
# 라벨 컬럼이 있는지 확인하는 것은 중요
if 'label' not in sampled_df.columns:
    print("[ERROR] 샘플링된 데이터에 'label' 컬럼이 없습니다.")
    exit()

# X는 모델 학습에 사용될 특징들의 DataFrame
# 'label' 컬럼과 원본 'family' 컬럼은 특징에서 제외
X = sampled_df.drop(columns=['label'])
if 'family' in X.columns:
    X = X.drop(columns=['family'])
# y = sampled_df['label'] # 모델 학습 안 하므로 y는 사용 안 함

# <<<<< 학습에 사용될 최종 특징 컬럼 리스트 추출 및 저장 >>>>>
feature_columns_for_training = X.columns.tolist()
print(f"추출된 특징 컬럼 수: {len(feature_columns_for_training)}")
print("추출된 특징 컬럼명 (일부):", feature_columns_for_training[:5]) # 처음 5개만 출력

feature_list_path = os.path.join(MODEL_SAVE_DIR, FEATURE_COLUMNS_FILENAME)
try:
    joblib.dump(feature_columns_for_training, feature_list_path)
    print(f"학습에 사용될 특징 컬럼 리스트 저장 완료: {feature_list_path}")
except Exception as e:
    print(f"[ERROR] 특징 리스트 저장 중 오류 발생: {e}")

# --- 4. 학습/테스트 데이터 분할 (생략) ---
# X_train, X_test, y_train, y_test = train_test_split(...)

# --- 5. 데이터 스케일링 (생략) ---
# X_train_scaled = X_train
# X_test_scaled = X_test

# --- 6. 모델 선택 및 학습 (생략) ---
# model = lgb.LGBMClassifier(...)
# print("모델 학습 시작...")
# model.fit(X_train_scaled, y_train)
# print("모델 학습 완료.")

# --- 7. 모델 평가 (생략) ---
# y_pred = model.predict(X_test_scaled)
# ...

# --- 8. 모델 저장 (생략) ---
# model_path = os.path.join(MODEL_SAVE_DIR, MODEL_FILENAME)
# joblib.dump(model, model_path)
# print(f"\n모델 저장 완료: {model_path}")

print("\n--- 특징 컬럼 리스트 추출 및 저장 프로세스 완료 ---")
