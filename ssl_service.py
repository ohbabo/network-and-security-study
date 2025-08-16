

""" ssl원시코드 
from urllib.parse import urlparse
from requests.exceptions import Timeout,RequestException,SSLError
import requests

class SSLscan:
    def __init__ (self,url:str, timeout:int=3):
        
        self.url = url if '://' in url else 'https://' + url
        
        u = urlparse(self.url)

        if u.scheme != 'https' or not u.hostname:
            raise ValueError('value 에러 url이 https주소 형식이 아님')      

        self.timeout = timeout

    
    def __call__(self) ->bool:

        try:    
            requests.get(url=self.url,timeout=self.timeout,allow_redirects=True)
            return True
        
        except SSLError:
            return False
        
        except (TimeoutError,RequestException):
            return False
        

def ssl_scan(url):
    result = SSLscan(url)()
 """   
# ssl 코드
from urllib.parse import urlparse
import socket,ssl #
from datetime import datetime,timezone


class SSL_scan:
    
    def __init__(self,url:str,timeout: int =3):

        self.url = url if '://' in url else 'https://' + url # url 검증
        
        u = urlparse(self.url)
        if u.scheme != 'https' or not u.scheme:
            raise ValueError('url 주소 형식이 아닙니다')
        
        self.hostname = u.hostname
        self.timeout = timeout
        
    @staticmethod 
    def _parse_cert_time(s:str): #ssl 인증서의 유효기간 문자열을 파싱해 datetime 객체로 변환
        """인증서 시간 문자열"""

        try:
            dt =datetime.strptime(s,"%b %d %H: %M %s %Y %Z")
            #strptime : datetime -> 문자열 변환 p파싱 
            # "Jun 5 12:00:00 2025 GMT" → datetime(2025, 6, 5, 12, 0, 0)
            #strftime : 문자열 -> datetime 변환 f포멧
            #datetime(2025, 6, 5, 12, 0, 0) → "Jun 05 12:00:00 2025 GMT"

            return dt.replace(tzinfo = timezone.utc) 
        #변환된 datetime 객체에 UTC 시간대를 명시적으로
        #인증서 시간은 대부분 UTC(GMT) 기준이라서 timezone을 설정해야 계산 시혼동이 없음 

        except Exception:
            return None
        
    def _pick_cn(name_list): #cn : commonname 약자 추출 -> value 추출
        """subject/issuer 구조에서 commonName(cn)만 추출""" #cn : 예전 대표 라벨

        try:
            for tup in name_list: # name_list []에서 tup(튜플)로 뽑아낸다. 
                # 여기서 name_list는 issuer,subject가 있음.

                for k,v in tup: # tup(튜플) 에서 k:key ,value로 뽑아낸다.
                    if k.lower() == "commonname": # 여기서 k 키가 commonname 비교
                        # lower() 메서드는 문자열을 소문자로 통일해서 비교 일부 k가 대문자 섞여서 올수 있기떄문
                        
                        return v # 여기서 해당 value는 cn도메인 데이터이다 www.google.com
                                # hostbame = 내가 접속하고자 하는 대상
                                # cn: 서버 인증서가 주장하는 대상
        #이론

        except Exception:
            pass
        return None #예외이긴 한데 아무런 리턴값도 없네 error 내용도
    

    def detail(self)-> dict:
        """핸드셰이크 수행 후 인증서 정보를 딕셔너리로 반환""" 

        res = {
            "ok":False,"valid":False,"expired": None,
            "not_after": None, "subject_cn":None , "issuer_cn":None,
            "error":None 
        }     
        #res: result 약자
        # res <-- ssl 검증 결과 스키마(모두가 약속한 통일된 데이터틀)          

        try:
            host_idna= self.host.encode("idna").decode("ascii")  
            #host 도메인주소 www.google.com을 
            # encode 'idna' 퓨니코드로 str->byte변환
            # decode 'ascii' byte -> ascii 변환 
            #번거로운 이유 한글 다른나라 언어 도메인 주소를 공통 퓨니코드로 byte변환후 인간이 알아볼수 있는 ascii변환
            ctx = ssl.create_default_context() #tls에 사용할 보안 묶음 틀만 객체정의
            ctx.check_hostname = True  #도메인 일치검사 : 그 인증서가 지금 접속하는 호스트이름(sni,요청도메인) 정확히 같은지
            ctx.verify_mode = ssl.CERT_REQUIRED # 유효 인증서 필수 : 신뢰가능한 CA가 서명했는지, 유효기간이 맞는지

        
            with socket.create_connection((host_idna,443),timeout=self.timeout) as sock: #소켓으로 해당 호스트,포트로 전송
                with ctx.wrap_socket(sock,server_hostname=host_idna) as ssock:
                    #wrap: 감싸다  ->wrap_socket 소켓을 감싸다 암호통신 -> ssock 결과
                    cert = ssock.getpeercert() 

            #cert 데이터 구조
            #subject 타입:튜플 key,value  (((CountryName,'us')),(('organizationName',Example Inc'),),(('CommonName','example.com'),))
            # issurer 타입: 튜플 key,value 발급자 DN, subject랑 동일한 구조
            # version 타입:int 일반적으로 3 아마 지금 버젼이 3인거 같다.
            # serialNumber str (16진 문자열) 씨리얼 넘버 언제 사용하는 걸까.
            # notBefore,notAfter : str 예:'Aug 15 12:00:00 2025 GMT
            #subjectAltName tuple (('DNS','example.com'), ('DNS','www.example.com'), ('IP Address','93.184.216.34'))
            
            
            not_after = cert.get("notAfter") #cer에서 유효기간 가져옴
            dt_after = self.parse_cert_time(not_after) # 그 유효기간 문자열을 utc를 붙여 datatime객체
            expired = (dt_after is not None) and (dt_after < datetime.now(timezone.utc)) #현재시간 datetime객체와 유효기간이랑 비교 


            subject_cn = self._pick_cn(cert.get("subject",[]))#cn 데이터 받아옴
            issuer_cn = self._pick_cn(cert.get("issuer",[]))# 마찬가지



            res.update({ #스키마 대입
                "ok": True,
                "valid": (not expired),
                "expired": expired,
                "not_after": dt_after.isoformat() if dt_after else None,
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn
            })
        except ssl.SSLCertVerificationError as e:
            res["error"] = f"cert verify failed: {e}"
        except ssl.SSLError as e:
            res["error"] = f"ssl error: {e}"
        except socket.timeout:
            res["error"] = "timeout"
        except Exception as e:
            res["error"] = str(e)
        return res

    def __call__(self) -> bool:
        info = self.detail()
        return bool(info.get("valid"))
        
