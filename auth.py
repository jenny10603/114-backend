from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

fake_user_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT config
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = 30

oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_user_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user["username"]})
    response.set_cookie(
        key="jwt",
        value=access_token,
        httponly=True,
        samesite="lax"
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/user/me")
def me(token: Optional[str] = Depends(oauth2_schema), jwt_cookie: Optional[str] = Cookie(None)):
    if token:
        username = verify_token(token)
    elif jwt_cookie:
        username = verify_token(jwt_cookie)
    else:
        raise HTTPException(status_code=401, detail="Messing token or cookie")
    
    return {"message": "Hello, {username}! You are authenticated."}
