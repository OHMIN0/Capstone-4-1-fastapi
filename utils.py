### utils.py ###

import os
from config import UPLOAD_DIR # config.py 에서 UPLOAD_DIR 임포트

def ensure_upload_dir_exists():
    """
    설정 파일(config.py)에 정의된 업로드 디렉토리가 없으면 생성합니다.
    """
    if not os.path.exists(UPLOAD_DIR):
        try:
            os.makedirs(UPLOAD_DIR)
            print(f"[INFO] 업로드 디렉토리 생성: {UPLOAD_DIR}")
        except OSError as e:
            print(f"[ERROR] 업로드 디렉토리 생성 실패: {e}")
            # 실제 운영 환경에서는 더 강력한 오류 처리나 로깅이 필요할 수 있습니다.
            raise # 오류 발생 시 상위 호출자에게 전파
