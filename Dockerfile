    # Dockerfile

    # 1. ���̽� �̹��� ���� (Python 3.12 ���� ���� ���)
    FROM python:3.12-slim

    # 2. �۾� ���丮 ����
    WORKDIR /app

    # 3. �ý��� ��Ű�� ������Ʈ �� yara C ���̺귯�� ��ġ
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. ���̽� ���� ȯ�� ���� �� Ȱ��ȭ ��� ����
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. <<<<< �ɺ��� ��ũ ���� �߰� >>>>>
    # apt �� ��ġ�� libyara.so �� ���� ��ο��� venv ���� lib ��η� ��ũ ����
    # ���� ��ġ ��δ� /usr/lib/x86_64-linux-gnu/libyara.so �� ���ɼ��� ���� (�ƴϸ� ���� �α׿��� Ȯ�� �ʿ�)
    # ��� ���丮(/opt/venv/lib)�� ���� ��� ����Ͽ� ���� (-p �ɼ��� ���ʿ��� �� ����)
    RUN mkdir -p /opt/venv/lib && \
        ln -s /usr/lib/x86_64-linux-gnu/libyara.so /opt/venv/lib/libyara.so

    # 6. requirements.txt ���� �� ���̽� ��Ű�� ��ġ
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # 7. ���ø����̼� �ڵ� ��ü ����
    COPY . .

    # 8. ���ø����̼� ���� ��� (Railway�� �����ϴ� $PORT ȯ�� ���� ���)
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    