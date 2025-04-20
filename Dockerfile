    # Dockerfile

    # 1. ���̽� �̹��� ���� (Python 3.12 ���� ���� ���)
    FROM python:3.12-slim

    # 2. �۾� ���丮 ����
    WORKDIR /app

    # 3. �ý��� ��Ű�� ������Ʈ �� yara C ���̺귯�� ��ġ
    # apt-get install yara �� libyara.so �� /usr/lib/x86_64-linux-gnu/ �� ��ġ�Ѵٰ� ����
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. ���̽� ���� ȯ�� ���� �� Ȱ��ȭ ��� ����
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. <<<<< LD_LIBRARY_PATH ȯ�� ���� ���� �߰� >>>>>
    # ���� ���̺귯�� �˻� ��ο� apt �� ��ġ�� ���̺귯�� ��θ� �߰�
    ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

    # 6. requirements.txt ���� �� ���̽� ��Ű�� ��ġ
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    # 7. ���ø����̼� �ڵ� ��ü ����
    COPY . .

    # 8. ���ø����̼� ���� ��� (Railway�� �����ϴ� $PORT ȯ�� ���� ���)
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT
    