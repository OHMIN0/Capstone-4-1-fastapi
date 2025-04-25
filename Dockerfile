# Dockerfile

# 1. 踰좎씠�뒪 �씠誘몄�� �꽑�깮 (python:3.12 �씪諛� 踰꾩쟾 �쑀吏�)
FROM python:3.12

# 2. �옉�뾽 �뵒�젆�넗由� �꽕�젙
WORKDIR /app

# 3. �떆�뒪�뀥 �뙣�궎吏� �뾽�뜲�씠�듃 諛� 湲곕낯 鍮뚮뱶 �룄援� �꽕移� (YARA 愿��젴 紐⑤몢 �젣嫄�)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev cmake libssl-dev libffi-dev binutils curl \
        libmagic-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. �뙆�씠�뜫 媛��긽 �솚寃� �깮�꽦 諛� �솢�꽦�솕 寃쎈줈 �꽕�젙
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 5. LD_LIBRARY_PATH �솚寃� 蹂��닔 �꽕�젙 (�빋 �궡遺� �씪�씠釉뚮윭由� 寃쎈줈 - �쑀吏�)
# /app/lib �뵒�젆�넗由щ�� �씪�씠釉뚮윭由� 寃��깋 寃쎈줈�뿉 異붽��
# ENV LD_LIBRARY_PATH=/app/lib:$LD_LIBRARY_PATH

# 6. requirements.txt 蹂듭궗 諛� �뙆�씠�뜫 �뙣�궎吏� �꽕移�
COPY requirements.txt .
# requirements.txt �뿉 �룷�븿�맂 libyara.so ��� �샇�솚�릺�뒗 yara-python 踰꾩쟾 紐낆떆 (�삁: 4.2.3)
RUN pip install --no-cache-dir -r requirements.txt

# 7. �븷�뵆由ъ���씠�뀡 肄붾뱶 �쟾泥� 蹂듭궗 (lib/libyara.so �룷�븿)
# �씠 �떒怨꾩뿉�꽌 濡쒖뺄�쓽 lib/libyara.so 媛� /app/lib/libyara.so 濡� 蹂듭궗�맖
COPY . .

# 8. <<<<< libyara.so �뙆�씪�쓣 venv/lib 濡� 吏곸젒 蹂듭궗 諛� �떎�뻾 沅뚰븳 遺��뿬 (�옱�떆�룄) >>>>>
# 鍮뚮뱶 濡쒓렇 �솗�씤�슜 echo 異붽��
# /app/lib/libyara.so �뙆�씪 議댁옱 �솗�씤 �썑 蹂듭궗 諛� 沅뚰븳 �꽕�젙
RUN echo "--- Checking bundled libyara.so in /app/lib ---" && \
    ls -l /app/lib/libyara.so || echo "--- Bundled libyara.so not found in /app/lib! Check Git repo. ---" && \
    echo "--- Attempting to copy bundled libyara.so to /opt/venv/lib/ ---" && \
    mkdir -p /opt/venv/lib && \
    cp /app/lib/libyara.so /opt/venv/lib/libyara.so && \
    chmod +x /opt/venv/lib/libyara.so && \
    echo "--- Copy and chmod finished. Checking file existence and permissions in venv: ---" && \
    ls -l /opt/venv/lib/libyara.so || echo "--- File not found in /opt/venv/lib after copy! ---"

# 9. �븷�뵆由ъ���씠�뀡 �떎�뻾 紐낅졊 (踰덊샇 議곗젙�맖)
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
