# Dockerfile

# 1. 베이스 이미지 선택 (로컬 환경과 정확히 일치)
FROM python:3.12.6

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 시스템 패키지 업데이트 및 기본 빌드 도구 + OpenSSL 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev cmake libssl-dev libffi-dev binutils curl \
        libmagic-dev make automake libtool pkg-config \
        openssl libssl3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. 파이썬 가상 환경 생성 및 활성화 경로 설정
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 5. LD_LIBRARY_PATH 환경 변수 설정 제거 (Entrypoint에서 설정)
# ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

# 6. requirements.txt 복사 및 파이썬 패키지 설치
COPY requirements.txt .
# requirements.txt 에서 yara-python 라인 제거 또는 주석 처리됨
RUN pip install --no-cache-dir -r requirements.txt

# 7. 애플리케이션 코드 전체 복사 (lib 폴더는 포함하지 않음)
COPY . .

# 8. <<<<< Entrypoint 스크립트 직접 생성 및 실행 권한 부여 >>>>>
# COPY entrypoint.sh . 제거
# RUN sed -i 's/\r$//' entrypoint.sh && \ # sed 명령어 제거
# echo 명령어를 사용하여 entrypoint.sh 파일 내용 생성 (LF 줄 끝 보장)
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# /usr/lib/x86_64-linux-gnu 경로를 LD_LIBRARY_PATH 맨 앞에 추가' >> /app/entrypoint.sh && \
    echo '# 기존 LD_LIBRARY_PATH 값이 있다면 유지' >> /app/entrypoint.sh && \
    echo 'export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo 'echo "Entrypoint: LD_LIBRARY_PATH set to [$LD_LIBRARY_PATH]"' >> /app/entrypoint.sh && \
    echo 'echo "Entrypoint: Executing command: $@"' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Dockerfile의 CMD 에서 전달된 명령어를 실행' >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    # 생성된 스크립트에 실행 권한 부여
    chmod +x /app/entrypoint.sh

# 9. <<<<< ENTRYPOINT 설정 >>>>>
# 컨테이너 시작 시 entrypoint.sh 스크립트를 실행하도록 설정
ENTRYPOINT ["/app/entrypoint.sh"]

# 10. 기본 실행 명령 (Entrypoint 스크립트에 인자로 전달됨)
# 포트를 8000으로 고정
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
