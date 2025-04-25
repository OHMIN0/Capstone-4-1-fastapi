### main.py ###

# venv�뤃�뜑�뿉 �꽕移섎맂 fastapi紐⑤뱢�뿉�꽌 FastAPI瑜� �엫�룷�듃
## routers �뤃�뜑�쓽 upload 紐⑤뱢�뿉�꽌 router 媛앹껜瑜� �엫�룷�듃
from fastapi import FastAPI     
from routers import upload      


# --- FastAPI �븷�뵆由ъ���씠�뀡 �씤�뒪�꽩�뒪 �깮�꽦 ---
## title, description, version �벑��� �뿬湲곗꽌 愿�由ы빀�땲�떎.
app = FastAPI(
    title="PE �뙆�씪 遺꾩꽍 AI API (紐⑤뱢�솕 踰꾩쟾)",
    description="�뙆�씪 �뾽濡쒕뱶, HTML �꽌鍮�, PE �뙆�씪 遺꾩꽍 �슂泥� 泥섎━瑜� �닔�뻾�븯�뒗 紐⑤뱢�솕�맂 API �꽌踰꾩엯�땲�떎.",
    version="0.4.0",
)

# --- �씪�슦�꽣 �룷�븿 ---
## upload.py �뙆�씪�뿉�꽌 Endpoint寃쎈줈�뱾�씠 �젙�쓽�릱�뜕 router�씤�뒪�꽩�뒪瑜� FastAPI �빋�뿉 �룷�븿�떆�궡
## prefix="/api/v1" ��� 媛숈씠 寃쎈줈 �젒�몢�궗 / tags=["Upload & Analysis"]媛숈�� 臾몄꽌 遺꾨쪟 �깭洹� 異붽�� 媛��뒫 (�꽑�깮 �궗�빆)
app.include_router(upload.router)


# --- �븘�옒�뒗 �꽌踰� �떎�뻾 紐낅졊  ---
## �꽣誘몃꼸�뿉�꽌 uvicorn�쓣 吏곸젒 �떎�뻾
## uvicorn main:app --reload --host 0.0.0.0 --port 8000

## �씠 �뙆�씪 �옄泥대�� 吏곸젒 �떎�뻾�븷 寃쎌슦 (python main.py) uvicorn �꽌踰꾨�� 援щ룞�븯�룄濡� �꽕�젙 (�꽑�깮 �궗�빆)
if __name__ == "__main__":
    import uvicorn
    # reload=True�뒗 媛쒕컻 以묒뿉留� �궗�슜�븯怨�, 諛고룷 �떆�뿉�뒗 False濡� 蹂�寃쏀븯嫄곕굹 �젣嫄고빀�땲�떎.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

