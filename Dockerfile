    # Dockerfile

    # 1. 베이스 이미지 선택 (python:3.12 일반 버전 유지)
    FROM python:3.12

    # 2. 작업 디렉토리 설정
    WORKDIR /app

    # 3. 시스템 패키지 업데이트 및 빌드 도구 설치 (gcc 명시적 추가)
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            build-essential gcc python3-dev cmake libssl-dev libffi-dev binutils curl \
            make automake libtool pkg-config \
            libmagic-dev && \
        # ^^^ gcc 추가
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # <<<<< 진단: gcc 설치 확인 >>>>>
    RUN echo "--- Checking installed gcc version ---" && \
        gcc --version || echo "--- gcc command not found or failed ---" && \
        echo "--- gcc check complete ---"

    # 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. LD_LIBRARY_PATH 환경 변수 설정 (앱 내부 라이브러리 경로)
    ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

    # 6. requirements.txt 복사 및 파이썬 패키지 설치
    COPY requirements.txt .
    # requirements.txt 에 포함된 libyara.so 와 호환되는 yara-python 버전 명시 (예: 4.2.3)
    RUN pip install --no-cache-dir -r requirements.txt

    # 7. 애플리케이션 코드 전체 복사 (lib/libyara.so 포함)
    COPY . .

    # 8. 애플리케이션 실행 명령
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    