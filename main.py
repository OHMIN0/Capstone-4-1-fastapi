# main.py

# venv폴더에 설치된 fastapi모듈에서 FastAPI를 임포트
# routers 폴더의 upload 모듈에서 router 객체를 임포트
from fastapi import FastAPI
from routers import upload


# --- FastAPI 애플리케이션 인스턴스 생성 ---
# title, description, version 등은 여기서 관리합니다.
app = FastAPI(
    title="PE 파일 분석 AI API (모듈화 버전)",
    description="파일 업로드, HTML 서빙, PE 파일 분석 요청 처리를 수행하는 모듈화된 API 서버입니다.",
    version="0.4.0",
)

# --- 라우터 포함 ---
# upload.py 파일에서 Endpoint경로들이 정의됐던 router인스턴스를 FastAPI 앱에 포함시키네
# prefix="/api/v1" 와 같이 경로 접두사 / tags=["Upload & Analysis"]같은 문서 분류 태그 추가 가능 (선택 사항)
app.include_router(upload.router)


# --- 아래는 서버 실행 명령 ---
# 터미널에서 uvicorn을 직접 실행
# uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 이 파일 자체를 직접 실행할 경우 (python main.py) uvicorn 서버를 구동하도록 설정 (선택 사항)
if __name__ == "__main__":
    import uvicorn
    # reload=True는 개발 중에만 사용하고, 배포 시에는 False로 변경하거나 제거합니다.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

