# main.py

# venv폴더에 설치된 fastapi모듈에서 FastAPI를 임포트
# routers 폴더의 upload와 index모듈에서 router 객체를 임포트
from fastapi import FastAPI
from routers import index, upload 


# --- FastAPI 애플리케이션 인스턴스 생성 ---
# title, description, version 등은 여기서 관리합니다.
app = FastAPI(
    title="PE 파일 분석 AI API (모듈화 버전)",
    description="파일 업로드, HTML 서빙, PE 파일 분석 요청 처리를 수행하는 모듈화된 API 서버입니다.",
    version="0.4.0",
)

# --- 라우터 포함 ---
# upload.py에서 Endpoint경로들이 정의됐던 router인스턴스와
# index.py에서 정의됐던 라우터 인스턴스를 FastAPI 앱에 포함시킴.
app.include_router(upload.router)
app.include_router(index.router)
