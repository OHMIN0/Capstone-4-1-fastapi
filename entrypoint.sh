    #!/bin/sh

    # /usr/lib/x86_64-linux-gnu 경로를 LD_LIBRARY_PATH 맨 앞에 추가
    # 기존 LD_LIBRARY_PATH 값이 있다면 유지
    export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

    echo "Entrypoint: LD_LIBRARY_PATH set to [$LD_LIBRARY_PATH]"
    echo "Entrypoint: Executing command: $@"

    # Dockerfile의 CMD 에서 전달된 명령어를 실행
    exec "$@"
    