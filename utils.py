### utils.py ###

import os
from config import UPLOAD_DIR # config.py �뿉�꽌 UPLOAD_DIR �엫�룷�듃

def ensure_upload_dir_exists():
    """
    �꽕�젙 �뙆�씪(config.py)�뿉 �젙�쓽�맂 �뾽濡쒕뱶 �뵒�젆�넗由ш�� �뾾�쑝硫� �깮�꽦�빀�땲�떎.
    """
    if not os.path.exists(UPLOAD_DIR):
        try:
            os.makedirs(UPLOAD_DIR)
            print(f"[INFO] �뾽濡쒕뱶 �뵒�젆�넗由� �깮�꽦: {UPLOAD_DIR}")
        except OSError as e:
            print(f"[ERROR] �뾽濡쒕뱶 �뵒�젆�넗由� �깮�꽦 �떎�뙣: {e}")
            # �떎�젣 �슫�쁺 �솚寃쎌뿉�꽌�뒗 �뜑 媛뺣젰�븳 �삤瑜� 泥섎━�굹 濡쒓퉭�씠 �븘�슂�븷 �닔 �엳�뒿�땲�떎.
            raise # �삤瑜� 諛쒖깮 �떆 �긽�쐞 �샇異쒖옄�뿉寃� �쟾�뙆
