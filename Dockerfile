    # Dockerfile

    # 1. 베이스 이미지 선택 (python:3.12 일반 버전 유지)
    FROM python:3.12

    # 2. 작업 디렉토리 설정
    WORKDIR /app

    # 3. 시스템 패키지 업데이트 및 기본 빌드 도구 설치
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            build-essential python3-dev cmake libssl-dev libffi-dev binutils curl \
            libmagic-dev && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. requirements.txt 먼저 복사 및 설치 (코드 복사 전)
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # 6. <<<<< 진단: 코드 복사 전 lib 폴더 내용 확인 (빌드 컨텍스트) >>>>>
    # COPY 명령어 전에 로컬의 lib 폴더가 빌드 컨텍스트에 포함되었는지 확인
    # Dockerfile과 같은 위치에 lib 폴더가 있어야 함
    RUN echo "--- Checking for lib directory in build context before COPY ---" && \
        ls -l lib/ || echo "--- lib directory not found in build context! Check local folder and .dockerignore ---"

    # 7. 애플리케이션 코드 전체 복사 (lib/libyara.so 포함)
    COPY . .

    # 8. <<<<< 진단: 코드 복사 후 /app/lib 폴더 내용 확인 >>>>>
    RUN echo "--- Checking for libyara.so in /app/lib after COPY ---" && \
        ls -l /app/lib/libyara.so || echo "--- libyara.so not found in /app/lib! COPY failed or file missing in Git. ---"

    # 9. <<<<< LD_LIBRARY_PATH 설정 (CMD 에서 직접 설정 시도) >>>>>
    # ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH # 이 방식 대신 아래 CMD에서 설정

    # 10. 애플리케이션 실행 명령 (LD_LIBRARY_PATH 직접 설정 후 실행)
    # CMD ["sh", "-c", "export LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH && echo 'LD_LIBRARY_PATH is now: [$LD_LIBRARY_PATH]' && uvicorn main:app --host 0.0.0.0 --port 8000"]
    # 또는 더 간단하게 (기존 $LD_LIBRARY_PATH 무시)
    CMD ["sh", "-c", "export LD_LIBRARY_PATH=/app/lib && echo 'LD_LIBRARY_PATH set to: [$LD_LIBRARY_PATH]' && uvicorn main:app --host 0.0.0.0 --port 8000"]
    