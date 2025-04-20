# routers/upload.py

from fastapi import APIRouter, Request, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import shutil
import os
from typing import Dict, Any

# 현재 파일 기준 상위 디렉토리의 모듈 임포트
from config import UPLOAD_DIR       # 설정값
from utils import ensure_upload_dir_exists # 유틸리티 함수
from analysis import run_analysis   # 분석 함수

# APIRouter 인스턴스 생성: 이 라우터에 경로들을 등록합니다.
router = APIRouter()

# Jinja2 템플릿 설정
# main.py 와 마찬가지로 'templates' 디렉토리를 기준으로 설정합니다.
# uvicorn 실행 위치(프로젝트 루트) 기준 상대 경로입니다.
# 참고: 더 큰 애플리케이션에서는 의존성 주입(Depends)을 사용하여
# main.py에서 생성된 templates 객체를 공유하는 것이 더 일반적입니다.
templates = Jinja2Templates(directory="templates")


"메인 HTML 페이지 (home.html)를 렌더링하여 반환. (GET 요청 처리)"
@router.get("/", response_class=HTMLResponse)
async def read_home(request: Request):
    ensure_upload_dir_exists()
    return templates.TemplateResponse("home.html", {"request": request, "apiResponse": None})


"파일 업로드 및 분석 요청 처리. (Post방식 사용)"
"파일 저장 -> 분석 실행 -> 결과를 포함하는 HTML 페이지 렌더링"
@router.post("/upload", response_class=HTMLResponse)
async def upload_and_analyze_file(request: Request, peFile: UploadFile = File(...)):

    "파일을 저장할 경로인 /uploaded-files폴더가 존재하는지 확인"
    "없을 경우 폴더를 생성함"
    ensure_upload_dir_exists()

    "업로드받은 PE파일의 이름을 original_filename변수에 저장"
    "UPLOAD_DIR은 config.py에서 관리하므로, 수정 필요할 경우 거기서 바꾸면 됨."
    "업로드할 파일과 루트를 변수에 저장하고, 아래 try문에서 저장 및 AI분석 실행"
    original_filename = peFile.filename
    file_path = os.path.join(UPLOAD_DIR, original_filename)
    print(f"[INFO] 파일 업로드 요청 수신 (라우터): {original_filename}")

    api_response: Dict[str, Any] = {}

    try:
        # 파일 저장
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(peFile.file, buffer)
        print(f"[INFO] 파일 저장 성공 (라우터): {file_path}")

        # AI 분석 실행 (analysis.py의 함수 호출)
        api_response = run_analysis(file_path)
        
    except Exception as e:
        print(f"[ERROR] 파일 처리/분석 오류 (라우터): {original_filename} | 오류: {e}")
        api_response = {
            "file_path": original_filename,
            "is_malicious": None,
            "confidence": None,
            "analysis_time": 0.0,
            "message": f"파일 처리 또는 분석 중 오류 발생: {e}",
            "success": False
        }
    finally:
        await peFile.close() # 파일 핸들 닫기

    # 결과를 포함하여 home.html 템플릿을 렌더링함
    return templates.TemplateResponse("home.html", {
        "request": request,
        "apiResponse": api_response
    })

# 필요에 따라 이 라우터 파일에 관련된 다른 엔드포인트들을 추가할 수 있습니다.
# 예: @router.get("/results/{file_id}") 등
