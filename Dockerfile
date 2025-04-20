    # Dockerfile

    # 1. ���̽� �̹��� ���� (Python 3.12 ���� ���� ���)
    FROM python:3.12-slim

    # 2. �۾� ���丮 ����
    WORKDIR /app

    # 3. �ý��� ��Ű�� ������Ʈ �� yara C ���̺귯�� ��ġ
    # --no-install-recommends �� ���ʿ��� ��Ű�� ��ġ ����
    # apt-get clean �� /var/lib/apt/lists/* ������ �̹��� �뷮 ����ȭ
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. ���̽� ���� ȯ�� ���� �� Ȱ��ȭ ��� ����
    # ���� ȯ���� ����Ͽ� �ý��� ���̽�� �и�
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. requirements.txt ���� �� ���̽� ��Ű�� ��ġ
    COPY requirements.txt .
    # --no-cache-dir �� �̹��� �뷮�� ���̴� �� ����
    RUN pip install --no-cache-dir -r requirements.txt

    # 6. ���ø����̼� �ڵ� ��ü ����
    COPY . .

    # 7. ���ø����̼� ���� ��� (Railway�� �����ϴ� $PORT ȯ�� ���� ���)
    # CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"] # ���� ��Ʈ ��� (�� �����)
    # $PORT ������ ���� ����ϴ� ���� Railway���� �����
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT

    # ����: EXPOSE ��ɾ�� ����ȭ �����̸�, Railway�� $PORT�� ���� �����մϴ�.
    # EXPOSE 8080
    