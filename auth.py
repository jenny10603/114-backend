from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# 假資料
fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT 設定
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# -------------------------
# Token Utility Functions
# -------------------------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str, expected_type: str = "access"):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_type = payload.get("type")

        if username is None or token_type != expected_type:
            raise HTTPException(status_code=401, detail="Invalid token")

        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------------
# Login Route
# -------------------------
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": user["username"]})
    refresh_token = create_refresh_token({"sub": user["username"]})

    # Set cookies
    response.set_cookie(
        key="jwt",
        value=access_token,
        httponly=True,
        samesite="lax"
    )
    response.set_cookie(
        key="refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax"
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# -------------------------
# Protected Route
# -------------------------
@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), jwt_cookie: Optional[str] = Cookie(None)):
    # 允許兩種登入方式：header 或 cookie
    if token:
        username = verify_token(token, expected_type="access")
    elif jwt_cookie:
        username = verify_token(jwt_cookie, expected_type="access")
    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")

    return {"message": f"Hello, {username}! You are authenticated."}


# -------------------------
# Refresh Token Route
# -------------------------
@app.post("/refresh")
def refresh_token(refresh_cookie: Optional[str] = Cookie(None), response: Response = None):
    if not refresh_cookie:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    # 驗證 refresh token
    username = verify_token(refresh_cookie, expected_type="refresh")

    # 產生新的 access token
    new_access_token = create_access_token({"sub": username})

    # 更新 access token cookie
    response.set_cookie(
        key="jwt",
        value=new_access_token,
        httponly=True,
        samesite="lax"
    )

    return {"access_token": new_access_token}
