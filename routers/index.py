# APIRouter 인스턴스 생성: 이 라우터에 경로들을 등록합니다.
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from utils import ensure_upload_dir_exists


router = APIRouter()
# Jinja2 템플릿 설정 ('templates' 디렉토리 기준)
templates = Jinja2Templates(directory="templates")


# 메인 HTML 페이지 (home.html) 렌더링 (GET /)
@router.get("/", response_class=HTMLResponse)
async def read_home(request: Request):
    """
    맨 처음이므로, 반환값(apiResponse)가 없는 home.html만을 렌더링해서 띄워줌
    """
    ensure_upload_dir_exists() # 업로드 디렉토리 확인 및 생성 // 함수 내용은 utils.py에 존재
    # 초기 페이지 렌더링 시 apiResponse는 None으로 전달
    return templates.TemplateResponse("home.html", {"request": request, "apiResponse": None})
