#API 관련 구조랑 메서드,스키마등은 그냥 GPT에게 물어보는게 더빠름.

import os,time
import vt
from urllib3.poolmanager import pool_classes_by_scheme


def require_key()->str:

    return "비밀"


def _norm(url) ->str:

    url1 = (url or "").strip()
    return url1 if "://" in url1 else "https://"+url1



#VT 정밀 검사(패키지 버젼)

def vt_scan(url:str, #입력 받을 값 url
            threshold : float =0.3, #임계값
            #timeout : int =5 ,
            #poll_attempts :  int= 3,
            #poll_interval : int =1.5,
            )->dict:

    key= require_key()
    u = _norm(url)

    #초기값 설정 vt캐시,제출상태  =False 정의

    vt_cashed,submitted = False,False
    try:
        with vt.Client(key,timeout=3) as vt_client:
            url_id = vt.url_id(u) # vt 자체적으로 해당 url id 생성

            try:
                url_obj =  vt_client.getobject(f"urls/{url_id}") #만약에 안불러 와진다면?
                cashed = True #vt 데이터베이스에 있음

            except vt.error.APIError as e:

                #만약 정보가 없는 url_id라면
                if e.code == 404:

                    analysis= vt_client.scan_url(url_id) #analysis 분석
                    submitted = True # vt 데이터 베이스에 없어서 내가 새로 제출함

                    for _ in 3:
                        analysis_success= vt_client.get_object(f"analysis/{analysis.id}")

                        if getattr(analysis_success,"status","") == "completed":
                            break

                        time.sleep(1.5)

                    url_obj = vt_client.get_object(f"urls/{url_id}")
                else:
                    return {
                            "ok":False,
                            "vt_cashed":False,
                            "submitted":False,
                            "phishing": None,
                            "score": None,
                            "stats":{},
                            "message": f"조회 실패{e.message}"
                    }


            st = url_obj.last_analysis_stats or {}
            #harmless, suspicious, malicious, undetected

            #for key in st:
            harmless = int(st.get("harmless"))
            suspicious = int(st.get("harmless"))
            malicious =  int(st.get("malicious"))
            undetected = int(st.get("undetected"))


            total = harmless+suspicious+malicious+undetected

            score = round(suspicious+malicious /total,4) if total else 0.0
            phishing = (malicious>=1) and (score >= threshold)

            return {
                "ok":True,
                "vt_cashed":vt_cashed,
                "submitted":submitted,
                "phishing" : phishing,
                "score" : score,
                "stats":{
                    "harmless":harmless, "suspicious":suspicious,"malicious": malicious, "undetected":undetected
                },
                "message" : "ok"
            }
    except Exception as e:
        return{
            "ok": False,
            "vt_cashed": vt_cashed,
            "submitted": submitted,
            "phishing": None,
            "score": None,
            "stats": {},
            "message": f"{e}"
        }



test = "http://www.target.site?#redirect=www.fake-target.site"

a= vt_scan(test) #vt scan이 에러나는데?





