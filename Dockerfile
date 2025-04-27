# Dockerfile

# 1. 베이스 이미지 선택 (python:3.12 일반 버전 유지)
FROM python:3.12

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 시스템 패키지 업데이트 및 기본 빌드 도구 설치 (YARA C 라이브러리 설치 제거)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev cmake libssl-dev libffi-dev binutils curl \
        libmagic-dev make automake libtool pkg-config && \
    # yara, libyara-dev 설치 제거됨
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 5. LD_LIBRARY_PATH 환경 변수 설정 제거

# 6. requirements.txt 복사 및 파이썬 패키지 설치
COPY requirements.txt .
# requirements.txt 에 yara-python 버전 명시 (예: 4.2.3)
# pip 이 yara-python 설치 시 필요한 C 라이브러리까지 처리해주기를 기대
RUN pip install --no-cache-dir -r requirements.txt

# 7. 애플리케이션 코드 전체 복사 (이제 lib/libyara.so 는 포함하지 않음)
COPY . .

# 8. libyara.so 복사 및 ldconfig 단계 제거

# 9. 애플리케이션 실행 명령 (번호 조정됨)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
