    # Dockerfile

    # 1. 베이스 이미지 선택 (Python 3.12 슬림 버전 사용)
    FROM python:3.12-slim

    # 2. 작업 디렉토리 설정
    WORKDIR /app

    # 3. 시스템 패키지 업데이트 및 yara C 라이브러리 설치
    # --no-install-recommends 는 불필요한 패키지 설치 방지
    # apt-get clean 및 /var/lib/apt/lists/* 삭제는 이미지 용량 최적화
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
    # 가상 환경을 사용하여 시스템 파이썬과 분리
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. requirements.txt 복사 및 파이썬 패키지 설치
    COPY requirements.txt .
    # --no-cache-dir 은 이미지 용량을 줄이는 데 도움
    RUN pip install --no-cache-dir -r requirements.txt

    # 6. 애플리케이션 코드 전체 복사
    COPY . .

    # 7. 애플리케이션 실행 명령 (Railway가 제공하는 $PORT 환경 변수 사용)
    # CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"] # 고정 포트 방식 (덜 권장됨)
    # $PORT 변수를 직접 사용하는 것이 Railway에서 권장됨
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT

    # 참고: EXPOSE 명령어는 문서화 목적이며, Railway는 $PORT로 직접 매핑합니다.
    # EXPOSE 8080
    