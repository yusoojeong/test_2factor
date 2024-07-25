
from datetime import datetime, timedelta

from fastapi import HTTPException, status

import jwt


SECRET_KEY = "your_secret_key"  # JWT 서명에 사용할 비밀 키
TEMP_SECRET_KEY = "your_temp_secret_key"  # 임시 JWT 서명에 사용할 비밀 키
ALGORITHM = "HS256"  # JWT 서명 알고리즘
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 토큰 유효 기간 (분)
TEMP_TOKEN_EXPIRE_MINUTES = 5   # 임시 토큰 유효 기간 (분)


def create_access_token(data: dict, token_type: str = "access"):
    to_encode = data.copy()
    minutes = ACCESS_TOKEN_EXPIRE_MINUTES if token_type == "access" else TEMP_TOKEN_EXPIRE_MINUTES
    secret_key = SECRET_KEY if token_type == "access" else TEMP_SECRET_KEY

    expires_delta = timedelta(minutes=minutes)
    expire = datetime.utcnow() + expires_delta

    to_encode.update({"exp": expire, "type": token_type})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str, token_type: str = "access"):
    secret_key = SECRET_KEY if token_type == "access" else TEMP_SECRET_KEY
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])

        token_type_in_payload = payload.get("type")
        if token_type_in_payload != token_type:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
