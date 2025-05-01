# utils.py

import os
# config.py 에서 UPLOAD_DIR 임포트
from config import UPLOAD_DIR
 
def ensure_upload_dir_exists():
    """
    설정 파일(config.py)에 정의된 업로드 디렉토리가 없으면 생성합니다.
    """
    if not os.path.exists(UPLOAD_DIR):
        try:
            os.makedirs(UPLOAD_DIR)
            print(f"[INFO] Upload Dir Create Complete : {UPLOAD_DIR}")
        except OSError as e:
            print(f"[ERROR] Upload Dir Create Failed : {e}")
            raise # 오류 발생 시 상위 호출자에게 전파

# 함수들 더 분리해서 여기서 한번에 다루고 싶은데,
# 지금으로써는 더 분리할만한 애들이 안보여요
