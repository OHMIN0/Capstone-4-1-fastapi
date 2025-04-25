# Dockerfile

# 1. 베이스 이미지 선택 (python:3.12 일반 버전 유지)
FROM python:3.12

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 시스템 패키지 업데이트 및 기본 빌드 도구 설치 (YARA 관련 모두 제거)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev cmake libssl-dev libffi-dev binutils curl \
        libmagic-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 5. LD_LIBRARY_PATH 환경 변수 설정 (앱 내부 라이브러리 경로 - 일단 유지)
# /app/lib 경로를 라이브러리 검색 경로에 추가
ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# 6. requirements.txt 복사 및 파이썬 패키지 설치
COPY requirements.txt .
# requirements.txt 에 포함된 libyara.so 와 호환되는 yara-python 버전 명시 (예: 4.2.3)
RUN pip install --no-cache-dir -r requirements.txt

# 7. 애플리케이션 코드 전체 복사 (lib/libyara.so 포함)
COPY . .

# 8. <<<<< libyara.so 파일을 venv/lib 로 직접 복사 >>>>>
# yara-python 이 계속 이 경로를 참조하는 것으로 보이므로, 복사 시도
# /app/lib 디렉토리가 COPY . . 이후에 존재한다고 가정
RUN echo "--- Copying bundled libyara.so to /opt/venv/lib/ ---" && \
    mkdir -p /opt/venv/lib && \
    cp /app/lib/libyara.so /opt/venv/lib/libyara.so && \
    echo "--- Copy finished. Checking file existence: ---" && \
    ls -l /opt/venv/lib/libyara.so || echo "--- File not found in /opt/venv/lib after copy! ---"

# 9. 애플리케이션 실행 명령 (번호 조정됨)
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
