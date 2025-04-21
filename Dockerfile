# Dockerfile

# 1. 베이스 이미지 선택 (python:3.12 일반 버전 유지)
FROM python:3.12

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 시스템 패키지 업데이트 및 YARA 컴파일에 필요한 빌드 도구 + libmagic 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev cmake libssl-dev libffi-dev binutils \
        curl make automake libtool pkg-config \
        libmagic-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. YARA 소스 코드 다운로드, 컴파일 및 설치 + 링커 설정 업데이트
ENV YARA_VERSION=4.2.3
RUN curl -L -o yara-${YARA_VERSION}.tar.gz "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" && \
    tar -xzf yara-${YARA_VERSION}.tar.gz && \
    rm yara-${YARA_VERSION}.tar.gz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --enable-magic --enable-dotnet --with-crypto && \
    make && \
    make install && \
    # <<<<< /usr/local/lib 경로를 링커 설정에 추가 >>>>>
    echo "/usr/local/lib" > /etc/ld.so.conf.d/yara.conf && \
    # <<<<< ldconfig 실행하여 링커 캐시 업데이트 >>>>>
    ldconfig && \
    # 설치 확인용 (선택 사항, 빌드 로그에서 확인)
    echo "--- Checking for compiled libyara.so in /usr/local/lib after ldconfig ---" && \
    ls -l /usr/local/lib/libyara* 2>/dev/null || echo "Compiled libyara.so not found in /usr/local/lib" && \
    echo "--- Check complete ---" && \
    # 소스 폴더 정리
    cd .. && \
    rm -rf yara-${YARA_VERSION}

# 5. 파이썬 가상 환경 생성 및 활성화 경로 설정
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 6. LD_LIBRARY_PATH 환경 변수 설정 (이제 불필요할 수 있으나, 안전하게 유지)
# ldconfig 로 시스템 캐시가 업데이트되었으므로 이 설정이 없어도 동작할 수 있지만,
# 만약을 위해 유지하는 것도 좋습니다. 또는 제거하고 테스트해볼 수도 있습니다.
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# 7. requirements.txt 복사 및 파이썬 패키지 설치
COPY requirements.txt .
# requirements.txt 에 yara-python==4.2.3 지정 권장
RUN pip install --no-cache-dir -r requirements.txt

# 8. 애플리케이션 코드 전체 복사
COPY . .

# 9. 애플리케이션 실행 명령
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
