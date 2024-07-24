from fastapi import FastAPI, Depends, HTTPException, status, Form, Response
from fastapi.security import OAuth2PasswordBearer
import io
import pyotp
import qrcode

app = FastAPI()


# 사용자 데이터베이스 (예: 사용자 시크릿 키 저장소)
user_db = {
    "test": {
        "secret": "JBSWY3DPEHPK3PXP",  # 이 시크릿 키는 사용자가 앱에 스캔해야 하는 키입니다.
        "username": "test",
        "password": "password"
    }
}


@app.post("/token")
async def login(username: str = Form(...), password: str = Form(...)):
    user = user_db.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return {"access_token": username, "token_type": "bearer"}


@app.post("/verify-otp")
async def verify_otp(username: str = Form(...), password: str = Form(...), otp: str = Form(...)):
    user = user_db.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    totp = pyotp.TOTP(user["secret"])
    if not totp.verify(otp):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")

    return {"message": "OTP verified successfully"}


# OTP QR코드 생성 엔드포인트 (테스트용)
@app.get("/generate-otp/{username}")
async def generate_otp(username: str):
    user = user_db.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    totp = pyotp.TOTP(user["secret"])
    qr_code = qrcode.make(
        totp.provisioning_uri(name=user["username"], issuer_name="Test Example app")
    )
    img_byte_arr = io.BytesIO()
    qr_code.save(img_byte_arr)
    img_byte_arr = img_byte_arr.getvalue()
    return Response(content=img_byte_arr, media_type="image/png")
