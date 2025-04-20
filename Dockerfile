    # Dockerfile

    # 1. 베이스 이미지 선택 (Python 3.12 슬림 버전 사용)
    FROM python:3.12-slim

    # 2. 작업 디렉토리 설정
    WORKDIR /app

    # 3. 시스템 패키지 업데이트 및 yara C 라이브러리 설치
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. <<<<< 심볼릭 링크 생성 추가 >>>>>
    # apt 로 설치된 libyara.so 의 예상 경로에서 venv 내부 lib 경로로 링크 생성
    # 실제 설치 경로는 /usr/lib/x86_64-linux-gnu/libyara.so 일 가능성이 높음 (아니면 빌드 로그에서 확인 필요)
    # 대상 디렉토리(/opt/venv/lib)가 없을 경우 대비하여 생성 (-p 옵션은 불필요할 수 있음)
    RUN mkdir -p /opt/venv/lib && \
        ln -s /usr/lib/x86_64-linux-gnu/libyara.so /opt/venv/lib/libyara.so

    # 6. requirements.txt 복사 및 파이썬 패키지 설치
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # 7. 애플리케이션 코드 전체 복사
    COPY . .

    # 8. 애플리케이션 실행 명령 (Railway가 제공하는 $PORT 환경 변수 사용)
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    