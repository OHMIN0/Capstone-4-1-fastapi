    # Dockerfile

    # 1. 베이스 이미지 선택 (python:3.12 일반 버전 유지)
    FROM python:3.12

    # 2. 작업 디렉토리 설정
    WORKDIR /app

    # 3. 시스템 패키지 업데이트 및 yara C 라이브러리 + 빌드 도구 설치
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara libyara-dev build-essential python3-dev cmake libssl-dev libffi-dev && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. <<<<< LD_LIBRARY_PATH 환경 변수 설정 (Dockerfile ENV 사용) >>>>>
    # apt 로 설치된 라이브러리 경로(/usr/lib/x86_64-linux-gnu)를 명시적으로 추가
    ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

    # 6. requirements.txt 복사 및 파이썬 패키지 설치
    COPY requirements.txt .
    # requirements.txt 에 yara-python==4.2.3 또는 4.2.0 지정되어 있어야 함
    RUN pip install --no-cache-dir -r requirements.txt

    # 7. 애플리케이션 코드 전체 복사
    COPY . .

    # 8. 애플리케이션 실행 명령 (원래대로 복구)
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    