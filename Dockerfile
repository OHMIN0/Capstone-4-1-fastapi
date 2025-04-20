    # Dockerfile

    # 1. 베이스 이미지 선택 (Python 3.12 슬림 버전 사용)
    FROM python:3.12-slim

    # 2. 작업 디렉토리 설정
    WORKDIR /app

    # 3. 시스템 패키지 업데이트 및 yara C 라이브러리 설치
    # apt-get install yara 가 libyara.so 를 /usr/lib/x86_64-linux-gnu/ 에 설치한다고 가정
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. <<<<< LD_LIBRARY_PATH 환경 변수 설정 추가 >>>>>
    # 공유 라이브러리 검색 경로에 apt 로 설치된 라이브러리 경로를 추가
    ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

    # 6. requirements.txt 복사 및 파이썬 패키지 설치
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # 7. 애플리케이션 코드 전체 복사
    COPY . .

    # 8. 애플리케이션 실행 명령 (Railway가 제공하는 $PORT 환경 변수 사용)
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    