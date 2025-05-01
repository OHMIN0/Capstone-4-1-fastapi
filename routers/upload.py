# routers/upload.py

from fastapi import APIRouter, Request, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import shutil
import os
from typing import Dict, Any

# --- 절대 경로 임포트 ---
# 프로젝트 루트 디렉토리에 있는 모듈들을 직접 임포트합니다.
from config import UPLOAD_DIR       # 업로드 경로 설정값
from utils import ensure_upload_dir_exists # 업로드 디렉토리 생성 유틸리티 함수
from analysis import run_analysis   # 특징 추출 및 분석 실행 함수 (동기 함수)


# APIRouter 인스턴스 생성: 이 라우터에 경로들을 등록합니다.
router = APIRouter()
# Jinja2 템플릿 설정 ('templates' 디렉토리 기준)
templates = Jinja2Templates(directory="templates")


# 파일 업로드 및 분석 처리 (POST /upload)
@router.post("/upload", response_class=HTMLResponse)
async def upload_and_analyze_file(request: Request, peFile: UploadFile = File(...)):
    """
    클라이언트로부터 pe파일을 업로드받을 경우, 분석 수행 후 결과 리턴.
    도중 문제 발생 시 오류정보를, 문제가 없을 경우 분석 결과를 반환

    - **request**: 템플릿 렌더링에 필요
    - **peFile**: 웹에서 클라이언트가 업로드한 파일의 객체 (`UploadFile`). html에서의 name속성의 값과 일치시켜야함
    """
    ensure_upload_dir_exists() # 업로드 디렉토리 확인 및 생성

    # 업로드받은 pe파일명을 그대로 백엔드에서 사용될 파일명으로 활용하기 위함
    original_filename = peFile.filename

    # 업로드된 파일을 저장할 전체 경로 생성
    file_path = os.path.join(UPLOAD_DIR, original_filename)
    print(f"[INFO] File upload request reception... (Router): {original_filename}")

    # 최종적으로 템플릿에 전달될 결과 딕셔너리
    api_response: Dict[str, Any] = {}

    try:
        # 1. 파일 저장
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(peFile.file, buffer)
        print(f"[INFO] File upload complete! (Router): {file_path}")

        # 2. 분석 실행 (analysis.py의 run_analysis 함수 호출)
        # run_analysis는 분석 결과를 담은 딕셔너리를 반환할 예정
        analysis_result = run_analysis(file_path)

        # 3. 템플릿에 전달할 api_response의 구조
        # run_analysis 결과에서 필요한 정보(is_malicious)를 포함하고,
        # 템플릿에서 사용할 success 플래그와 다른 메시지를 추가
        api_response = {
            "success": analysis_result.get("success", False), # run_analysis 결과의 success 값 사용 (없으면 False)
            "message": analysis_result.get("message", "분석 완료 (상세 메시지 없음)"), # run_analysis 결과의 message 사용
            "is_malicious": analysis_result.get("is_malicious"), # run_analysis 결과의 is_malicious 값 (없으면 None)
            # 필요 시 다른 최소한의 정보 추가 가능 (예: 분석했던 파일명 등)
            "filename": original_filename
        }
        # 추후 run_analysis() 자체가 is_malicious 만 반환하도록 수정된다면, 아래와 같은 식으로 수정해도 됨
        # api_response = {
        #     "success": True,                                          # 분석 함수가 오류 없이 반환되면 성공으로 간주
        #     "message": f"파일 '{original_filename}' 분석 완료.",       # 어차피 도중에 오류가 없었다면 분석이 성공한것이므로, 분석완료를 띄움
        #     "is_malicious": analysis_result                           # run_analysis 가 is_malicious 값만 반환한다고 가정
        # }

    except Exception as e:
        # 파일 저장 또는 run_analysis 호출 중 예외 발생 시
        print(f"[ERROR]  File processing/analysis errors (Router): {original_filename} | Exception: {e}")
        # 오류 발생 시, 오류 정보를 포함한 결과 딕셔너리 생성
        api_response = {
            "success": False,
            "message": f"파일 처리 또는 분석 중 오류 발생: {e}",
            "is_malicious": None, # 오류 시 악성 여부 알 수 없음
            "filename": original_filename
        }
    
    finally:
        await peFile.close()    # 업로드된 파일 리소스 해제


    # 분석 실패든, 성공이든 상관없이 최종 결과를 포함하여 home.html 템플릿 렌더링
    return templates.TemplateResponse("home.html", {
        "request": request,
        "apiResponse": api_response
    })

# 나중에 추가할 것들 생기면 아래에 엔드포인트 추가.
