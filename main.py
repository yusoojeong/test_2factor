from datetime import timedelta
import io

from fastapi import FastAPI, Depends, HTTPException, status, Form, Response
from fastapi.security import OAuth2PasswordBearer

import pyotp
import qrcode

from helpers import (
    create_access_token, verify_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
)


app = FastAPI()


# 사용자 데이터베이스 (예: 사용자 시크릿 키 저장소)
user_db = {
    "test": {
        "secret": None,  # 이 시크릿 키는 사용자가 앱에 스캔해야 하는 키입니다.
        "username": "test",
        "password": "password"
    }
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/token")
async def login(username: str = Form(...), password: str = Form(...)):
    user = user_db.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    create_qrcode = user.get("secret") is None
    temp_access_token = create_access_token(data={"sub": username}, token_type="temp")
    return {
        "temp_access_token": temp_access_token,
        "token_type": "bearer",
        "required_qrcode": create_qrcode,
    }


@app.post("/verify-otp")
async def verify_otp(token: str = Form(...), otp: str = Form(...)):
    username = verify_access_token(token, token_type="temp")
    user = user_db.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    totp = pyotp.TOTP(user["secret"])
    if not totp.verify(otp):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")

    access_token = create_access_token(data={"sub": username}, token_type="access")
    return {"access_token": access_token, "token_type": "bearer"}


# OTP QR코드 생성 엔드포인트 (테스트용)
@app.post("/generate-otp/{username}")
async def generate_otp(username: str, token: str = Form(...)):
    check_username = verify_access_token(token, token_type="temp")
    if username != check_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    user = user_db.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.get("secret"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User get qrcode")

    user["secret"] = pyotp.random_base32()
    totp = pyotp.TOTP(user["secret"])
    qr_code = qrcode.make(
        totp.provisioning_uri(name=user["username"], issuer_name="Test Example app")
    )
    img_byte_arr = io.BytesIO()
    qr_code.save(img_byte_arr)
    img_byte_arr = img_byte_arr.getvalue()
    return Response(content=img_byte_arr, media_type="image/png")
