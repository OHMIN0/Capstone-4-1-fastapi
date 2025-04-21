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
        # ^^^^^^^^^^^^ libmagic-dev 추가

    # 4. YARA 소스 코드 다운로드, 컴파일 및 설치 (yara-python 버전에 맞는 버전 선택, 예: 4.2.3)
    ENV YARA_VERSION=4.2.3
    RUN curl -L -o yara-${YARA_VERSION}.tar.gz "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" && \
        tar -xzf yara-${YARA_VERSION}.tar.gz && \
        rm yara-${YARA_VERSION}.tar.gz && \
        cd yara-${YARA_VERSION} && \
        ./bootstrap.sh && \
        # ./configure 옵션 수정: --enable-crypto -> --with-crypto
        ./configure --enable-magic --enable-dotnet --with-crypto && \
        make && \
        make install && \
        cd .. && \
        rm -rf yara-${YARA_VERSION} && \
        ldconfig # 설치된 라이브러리 시스템에 등록

    # 5. 파이썬 가상 환경 생성 및 활성화 경로 설정
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 6. LD_LIBRARY_PATH 환경 변수 설정 (소스 컴파일 설치 경로 추가)
    ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

    # 7. requirements.txt 복사 및 파이썬 패키지 설치
    COPY requirements.txt .
    # requirements.txt 에 yara-python==4.2.3 지정 권장
    RUN pip install --no-cache-dir -r requirements.txt

    # 8. 애플리케이션 코드 전체 복사
    COPY . .

    # 9. 애플리케이션 실행 명령
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    