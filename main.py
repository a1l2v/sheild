# main.py
import os
# Use passlib's builtin (pure-python) bcrypt backend to avoid incompatibilities
# with some installed `bcrypt` wheels (eg. bcrypt>=5.0.0 raises on >72-byte inputs
# during passlib's backend detection). Enabling the builtin backend is safe
# for development and avoids the runtime ValueError seen during register.
os.environ.setdefault("PASSLIB_BUILTIN_BCRYPT", "1")
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
from uuid import uuid4
from bson.objectid import ObjectId

# ---------------- Settings ----------------
class Settings(BaseSettings):
    MONGO_URI: str = Field("mongodb://localhost:27017", env="MONGO_URI")
    MONGO_DB: str = Field("fastapi_auth_db", env="MONGO_DB")
    SESSION_TOKEN_TTL_DAYS: int = Field(30, env="SESSION_TOKEN_TTL_DAYS")
    # you can add other env vars here

    class Config:
        env_file = ".env"

settings = Settings()

# ---------------- Password hashing ----------------
# Use bcrypt_sha256 to avoid the 72-byte bcrypt limit.
# This internally sha256-hashes long passwords before bcrypt so you don't lose entropy.
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

def hash_password(password: str) -> str:
    # Passlib handles string input; no manual truncation needed with bcrypt_sha256.
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ---------------- Pydantic models ----------------
class RegisterIn(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None

class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    session_token: str
    expires_at: Optional[datetime] = None

class UserOut(BaseModel):
    id: str
    username: str
    full_name: Optional[str] = None
    logged_in: bool

# ---------------- App & Mongo client ----------------
app = FastAPI(title="FastAPI Auth (session token + logged_in flag)")

mongo_client: Optional[AsyncIOMotorClient] = None
db = None

@app.on_event("startup")
async def startup_db_client():
    global mongo_client, db
    mongo_client = AsyncIOMotorClient(settings.MONGO_URI)
    db = mongo_client[settings.MONGO_DB]
    # make username unique (safe to call repeatedly)
    await db["users"].create_index("username", unique=True)
    app.state.db = db

@app.on_event("shutdown")
async def shutdown_db_client():
    global mongo_client
    if mongo_client:
        mongo_client.close()

# ---------------- Helper DB functions ----------------
async def get_user_doc_by_username(username: str) -> Optional[dict]:
    return await db["users"].find_one({"username": username})

async def get_user_doc_by_token(token: str) -> Optional[dict]:
    if not token:
        return None
    return await db["users"].find_one({"session_token": token})

async def create_user_doc(payload: RegisterIn) -> dict:
    # create document with hashed password
    doc = {
        "username": payload.username,
        "hashed_password": hash_password(payload.password),
        "full_name": payload.full_name,
        "disabled": False,
        "logged_in": False,
        "session_token": None,
        "session_expires_at": None,
        "created_at": datetime.utcnow(),
    }
    res = await db["users"].insert_one(doc)
    doc["_id"] = res.inserted_id
    # don't return hashed password
    doc.pop("hashed_password", None)
    return doc

# ---------------- Auth logic (flag + session token) ----------------
def make_session_token() -> str:
    return uuid4().hex

@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(user: RegisterIn):
    existing = await get_user_doc_by_username(user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    doc = await create_user_doc(user)
    return UserOut(id=str(doc["_id"]), username=doc["username"], full_name=doc.get("full_name"), logged_in=doc.get("logged_in", False))

@app.post("/login", response_model=TokenOut)
async def login(body: LoginIn):
    """
    Verify credentials. If correct:
    - set logged_in = True
    - create & store a session_token (opaque random string)
    - return session_token to client
    """
    user_doc = await get_user_doc_by_username(body.username)
    if not user_doc:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    hashed = user_doc.get("hashed_password")
    if not hashed or not verify_password(body.password, hashed):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if user_doc.get("disabled"):
        raise HTTPException(status_code=403, detail="User disabled")

    token = make_session_token()
    # Optionally set expiry time if you want sessions to auto-expire
    expires_at = datetime.utcnow() + timedelta(days=int(settings.SESSION_TOKEN_TTL_DAYS))

    await db["users"].update_one(
        {"_id": user_doc["_id"]},
        {"$set": {"logged_in": True, "session_token": token, "session_expires_at": expires_at}}
    )

    return TokenOut(session_token=token, expires_at=expires_at)

@app.post("/signout", status_code=status.HTTP_200_OK)
async def signout(authorization: Optional[str] = Header(None)):
    """
    Client should send header: Authorization: Session <session_token>
    This will clear the logged_in flag and remove the token.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "session" or not token:
        raise HTTPException(status_code=401, detail="Invalid authorization header (expected 'Session <token>')")

    user_doc = await get_user_doc_by_token(token)
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid session token")

    await db["users"].update_one(
        {"_id": user_doc["_id"]},
        {"$set": {"logged_in": False}, "$unset": {"session_token": "", "session_expires_at": ""}}
    )
    return {"detail": "Signed out"}

# ---------------- Protected dependency & example ----------------
async def require_session(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "session" or not token:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    user_doc = await get_user_doc_by_token(token)
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid session token")
    if not user_doc.get("logged_in"):
        raise HTTPException(status_code=401, detail="Session not active (user not logged in)")
    if user_doc.get("disabled"):
        raise HTTPException(status_code=403, detail="User disabled")
    return UserOut(id=str(user_doc["_id"]), username=user_doc["username"], full_name=user_doc.get("full_name"), logged_in=True)

@app.get("/protected")
async def protected_route(current_user: UserOut = Depends(require_session)):
    return {"message": f"Hello {current_user.username}, you are signed in."}

if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
