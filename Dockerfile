    # Dockerfile

    # 1. 踰좎씠�뒪 �씠誘몄�� �꽑�깮 (Python 3.12 �뒳由� 踰꾩쟾 �궗�슜)
    FROM python:3.12-slim

    # 2. �옉�뾽 �뵒�젆�넗由� �꽕�젙
    WORKDIR /app

    # 3. �떆�뒪�뀥 �뙣�궎吏� �뾽�뜲�씠�듃 諛� yara C �씪�씠釉뚮윭由� �꽕移�
    # --no-install-recommends �뒗 遺덊븘�슂�븳 �뙣�궎吏� �꽕移� 諛⑹��
    # apt-get clean 諛� /var/lib/apt/lists/* �궘�젣�뒗 �씠誘몄�� �슜�웾 理쒖쟻�솕
    RUN apt-get update && \
        apt-get install -y --no-install-recommends yara && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    # 4. �뙆�씠�뜫 媛��긽 �솚寃� �깮�꽦 諛� �솢�꽦�솕 寃쎈줈 �꽕�젙
    # 媛��긽 �솚寃쎌쓣 �궗�슜�븯�뿬 �떆�뒪�뀥 �뙆�씠�뜫怨� 遺꾨━
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"

    # 5. requirements.txt 蹂듭궗 諛� �뙆�씠�뜫 �뙣�궎吏� �꽕移�
    COPY requirements.txt .
    # --no-cache-dir ��� �씠誘몄�� �슜�웾�쓣 以꾩씠�뒗 �뜲 �룄���
    RUN pip install --no-cache-dir -r requirements.txt

    # 6. �븷�뵆由ъ���씠�뀡 肄붾뱶 �쟾泥� 蹂듭궗
    COPY . .

    # 7. �븷�뵆由ъ���씠�뀡 �떎�뻾 紐낅졊 (Railway媛� �젣怨듯븯�뒗 $PORT �솚寃� 蹂��닔 �궗�슜)
    # CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"] # 怨좎젙 �룷�듃 諛⑹떇 (�뜙 沅뚯옣�맖)
    # $PORT 蹂��닔瑜� 吏곸젒 �궗�슜�븯�뒗 寃껋씠 Railway�뿉�꽌 沅뚯옣�맖
    CMD uvicorn main:app --host 0.0.0.0 --port $PORT

    # 李멸퀬: EXPOSE 紐낅졊�뼱�뒗 臾몄꽌�솕 紐⑹쟻�씠硫�, Railway�뒗 $PORT濡� 吏곸젒 留ㅽ븨�빀�땲�떎.
    # EXPOSE 8080
    