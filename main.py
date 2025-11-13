import os
from datetime import datetime, timedelta, timezone, date
from typing import Optional, Literal, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db
from schemas import (
    Division, User as UserSchema, Account,
    CashEntry, ReceivableEntry, PayableEntry,
    ActivityLog, Notification
)

# Environment / Security
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

# Use pbkdf2_sha256 to avoid bcrypt backend issues in some environments
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(title="PT Padud Jaya Putera Accounting API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    division_id: Optional[str] = None

class UserPublic(BaseModel):
    username: str
    email: str
    role: str
    division_id: Optional[str] = None

# Helper functions

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserPublic:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        division_id: Optional[str] = payload.get("division_id")
        if username is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return UserPublic(username=username, email="", role=role, division_id=division_id)


def require_role(required: Literal["SUPER_ADMIN", "ADMIN_DIVISI"]):
    def checker(user: UserPublic = Depends(get_current_user)):
        if required == "SUPER_ADMIN" and user.role != "SUPER_ADMIN":
            raise HTTPException(status_code=403, detail="Forbidden: Super Admin only")
        return user
    return checker


# Seed initial data if collections empty
@app.on_event("startup")
async def seed_initial():
    if db is None:
        return
    if db["user"].count_documents({}) == 0:
        super_admin = {
            "username": "superadmin",
            "email": "super@padud.co.id",
            "hashed_password": get_password_hash("admin123"),
            "role": "SUPER_ADMIN",
            "division_id": None,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        db["user"].insert_one(super_admin)
    if db["division"].count_documents({}) == 0:
        db["division"].insert_many([
            {"name": "Keuangan", "code": "FIN", "is_active": True},
            {"name": "Pemasaran", "code": "MKT", "is_active": True},
            {"name": "Produksi", "code": "PRD", "is_active": True},
            {"name": "Gudang", "code": "GUD", "is_active": True},
            {"name": "HRD", "code": "HRD", "is_active": True},
        ])
    if db["account"].count_documents({}) == 0:
        db["account"].insert_many([
            {"code": "101", "name": "Kas Besar", "type": "asset", "is_active": True},
            {"code": "102", "name": "Bank", "type": "asset", "is_active": True},
            {"code": "201", "name": "Utang Usaha", "type": "liability", "is_active": True},
            {"code": "301", "name": "Modal", "type": "equity", "is_active": True},
            {"code": "401", "name": "Penjualan", "type": "revenue", "is_active": True},
            {"code": "501", "name": "Beban Umum", "type": "expense", "is_active": True},
        ])


# Public endpoints
@app.get("/health")
async def health():
    status_obj = {"backend": "ok", "time": datetime.now(timezone.utc).isoformat()}
    try:
        status_obj["database"] = "ok" if db is not None and db.list_collection_names() is not None else "down"
    except Exception:
        status_obj["database"] = "down"
    return status_obj


# Auth
class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/auth/login", response_model=Token)
async def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db["user"].find_one({"username": payload.username, "is_active": True})
    if not user or not verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    token = create_access_token({
        "sub": user["username"],
        "role": user["role"],
        "division_id": user.get("division_id")
    })
    return Token(access_token=token)


@app.get("/auth/me", response_model=UserPublic)
async def me(user: UserPublic = Depends(get_current_user)):
    if db is not None:
        doc = db["user"].find_one({"username": user.username})
        if doc:
            return UserPublic(username=doc["username"], email=doc.get("email", ""), role=doc["role"], division_id=doc.get("division_id"))
    return user


# Users (Super Admin only)
class CreateUser(BaseModel):
    username: str
    email: str
    password: str
    role: Literal["SUPER_ADMIN", "ADMIN_DIVISI"]
    division_id: Optional[str] = None


@app.post("/users", dependencies=[Depends(require_role("SUPER_ADMIN"))])
async def create_user(payload: CreateUser):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    if db["user"].find_one({"username": payload.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    doc = {
        "username": payload.username,
        "email": payload.email,
        "hashed_password": get_password_hash(payload.password),
        "role": payload.role,
        "division_id": payload.division_id,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    db["user"].insert_one(doc)
    return {"message": "User created"}


@app.get("/users", dependencies=[Depends(require_role("SUPER_ADMIN"))])
async def list_users(role: Optional[str] = None, division_id: Optional[str] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    query: Dict[str, Any] = {}
    if role:
        query["role"] = role
    if division_id:
        query["division_id"] = division_id
    users = list(db["user"].find(query, {"hashed_password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])  # make JSON serializable
    return {"data": users}


# Divisions
@app.get("/divisions")
async def get_divisions():
    divisions = list(db["division"].find({"is_active": True})) if db is not None else []
    for d in divisions:
        d["_id"] = str(d["_id"])  # json safe
    return {"data": divisions}


# Accounts (COA)
@app.get("/accounts")
async def get_accounts(type: Optional[str] = None):
    if db is None:
        return {"data": []}
    query = {"is_active": True}
    if type:
        query["type"] = type
    accounts = list(db["account"].find(query))
    for a in accounts:
        a["_id"] = str(a["_id"])  # json safe
    return {"data": accounts}


# Finance Endpoints
class CashIn(BaseModel):
    date: date
    type: Literal["penerimaan", "pengeluaran"]
    account_code: str
    amount: float = Field(..., gt=0)
    description: Optional[str] = None
    division_id: Optional[str] = None  # only superadmin can set arbitrary division


@app.post("/finance/cash")
async def add_cash(item: CashIn, user: UserPublic = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    division_id = item.division_id if user.role == "SUPER_ADMIN" and item.division_id else user.division_id
    if user.role == "ADMIN_DIVISI" and (division_id is None or division_id != user.division_id):
        raise HTTPException(status_code=403, detail="Access denied for division")
    doc = {
        "date": item.date.isoformat(),
        "division_id": division_id,
        "type": item.type,
        "account_code": item.account_code,
        "amount": item.amount,
        "description": item.description,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    db["cashentry"].insert_one(doc)
    return {"message": "Saved"}


@app.get("/finance/cash")
async def list_cash(
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    division_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    user: UserPublic = Depends(get_current_user)
):
    if db is None:
        return {"data": [], "total": 0}
    if user.role == "ADMIN_DIVISI":
        division_id = user.division_id
    query: Dict[str, Any] = {}
    if division_id:
        query["division_id"] = division_id
    if date_from or date_to:
        q: Dict[str, Any] = {}
        if date_from:
            q["$gte"] = date_from.isoformat()
        if date_to:
            q["$lte"] = date_to.isoformat()
        query["date"] = q
    total = db["cashentry"].count_documents(query)
    docs = list(db["cashentry"].find(query).skip((page-1)*page_size).limit(page_size).sort("date", 1))
    for d in docs:
        d["_id"] = str(d["_id"])  # json safe
    return {"data": docs, "total": total}


# Receivables
class ReceivableIn(BaseModel):
    date: date
    status: Literal["baru", "tertagih", "macet"]
    customer: str
    amount: float = Field(..., gt=0)
    description: Optional[str] = None
    division_id: Optional[str] = None


@app.post("/finance/receivables")
async def add_receivable(item: ReceivableIn, user: UserPublic = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    division_id = item.division_id if user.role == "SUPER_ADMIN" and item.division_id else user.division_id
    if user.role == "ADMIN_DIVISI" and (division_id is None or division_id != user.division_id):
        raise HTTPException(status_code=403, detail="Access denied for division")
    doc = item.model_dump()
    doc["division_id"] = division_id
    doc["date"] = item.date.isoformat()
    doc["created_at"] = datetime.now(timezone.utc)
    doc["updated_at"] = datetime.now(timezone.utc)
    db["receivableentry"].insert_one(doc)
    return {"message": "Saved"}


@app.get("/finance/receivables")
async def list_receivables(
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    division_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    user: UserPublic = Depends(get_current_user)
):
    if db is None:
        return {"data": [], "total": 0}
    if user.role == "ADMIN_DIVISI":
        division_id = user.division_id
    query: Dict[str, Any] = {}
    if division_id:
        query["division_id"] = division_id
    if date_from or date_to:
        q: Dict[str, Any] = {}
        if date_from:
            q["$gte"] = date_from.isoformat()
        if date_to:
            q["$lte"] = date_to.isoformat()
        query["date"] = q
    total = db["receivableentry"].count_documents(query)
    docs = list(db["receivableentry"].find(query).skip((page-1)*page_size).limit(page_size).sort("date", 1))
    for d in docs:
        d["_id"] = str(d["_id"])  # json safe
    return {"data": docs, "total": total}


# Payables
class PayableIn(BaseModel):
    date: date
    status: Literal["baru", "dibayar"]
    supplier: str
    amount: float = Field(..., gt=0)
    description: Optional[str] = None
    division_id: Optional[str] = None


@app.post("/finance/payables")
async def add_payable(item: PayableIn, user: UserPublic = Depends(get_current_user)):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    division_id = item.division_id if user.role == "SUPER_ADMIN" and item.division_id else user.division_id
    if user.role == "ADMIN_DIVISI" and (division_id is None or division_id != user.division_id):
        raise HTTPException(status_code=403, detail="Access denied for division")
    doc = item.model_dump()
    doc["division_id"] = division_id
    doc["date"] = item.date.isoformat()
    doc["created_at"] = datetime.now(timezone.utc)
    doc["updated_at"] = datetime.now(timezone.utc)
    db["payableentry"].insert_one(doc)
    return {"message": "Saved"}


@app.get("/finance/payables")
async def list_payables(
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    division_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    user: UserPublic = Depends(get_current_user)
):
    if db is None:
        return {"data": [], "total": 0}
    if user.role == "ADMIN_DIVISI":
        division_id = user.division_id
    query: Dict[str, Any] = {}
    if division_id:
        query["division_id"] = division_id
    if date_from or date_to:
        q: Dict[str, Any] = {}
        if date_from:
            q["$gte"] = date_from.isoformat()
        if date_to:
            q["$lte"] = date_to.isoformat()
        query["date"] = q
    total = db["payableentry"].count_documents(query)
    docs = list(db["payableentry"].find(query).skip((page-1)*page_size).limit(page_size).sort("date", 1))
    for d in docs:
        d["_id"] = str(d["_id"])  # json safe
    return {"data": docs, "total": total}


# Summary
@app.get("/finance/summary")
async def finance_summary(
    division_id: Optional[str] = None,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    user: UserPublic = Depends(get_current_user)
):
    if db is None:
        return {"cash": 0, "receivables": {"baru": 0, "tertagih": 0, "macet": 0}, "payables": {"baru": 0, "dibayar": 0}}
    if user.role == "ADMIN_DIVISI":
        division_id = user.division_id
    query: Dict[str, Any] = {}
    if division_id:
        query["division_id"] = division_id
    if date_from or date_to:
        q: Dict[str, Any] = {}
        if date_from:
            q["$gte"] = date_from.isoformat()
        if date_to:
            q["$lte"] = date_to.isoformat()
        query["date"] = q

    # Cash balance: penerimaan - pengeluaran
    cash_docs = list(db["cashentry"].find(query))
    cash_in = sum(d.get("amount", 0) for d in cash_docs if d.get("type") == "penerimaan")
    cash_out = sum(d.get("amount", 0) for d in cash_docs if d.get("type") == "pengeluaran")
    cash_balance = cash_in - cash_out

    # Receivables summary
    rec_docs = list(db["receivableentry"].find(query))
    receivables = {
        "baru": sum(d.get("amount", 0) for d in rec_docs if d.get("status") == "baru"),
        "tertagih": sum(d.get("amount", 0) for d in rec_docs if d.get("status") == "tertagih"),
        "macet": sum(d.get("amount", 0) for d in rec_docs if d.get("status") == "macet"),
    }

    # Payables summary
    pay_docs = list(db["payableentry"].find(query))
    payables = {
        "baru": sum(d.get("amount", 0) for d in pay_docs if d.get("status") == "baru"),
        "dibayar": sum(d.get("amount", 0) for d in pay_docs if d.get("status") == "dibayar"),
    }

    return {
        "cash": cash_balance,
        "receivables": receivables,
        "payables": payables,
    }


# Activity and notifications
@app.post("/notifications/broadcast", dependencies=[Depends(require_role("SUPER_ADMIN"))])
async def broadcast(note: Notification):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    doc = note.model_dump()
    doc["created_at"] = datetime.now(timezone.utc)
    db["notification"].insert_one(doc)
    return {"message": "Broadcast sent"}


@app.get("/notifications")
async def get_notifications(user: UserPublic = Depends(get_current_user)):
    if db is None:
        return {"data": []}
    query: Dict[str, Any] = {"audience": {"$in": ["all"]}}
    if user.role == "ADMIN_DIVISI" and user.division_id:
        query = {"$or": [
            {"audience": "all"},
            {"audience": "division", "division_id": user.division_id}
        ]}
    notes = list(db["notification"].find(query).sort("created_at", -1).limit(50))
    for n in notes:
        n["_id"] = str(n["_id"])
    return {"data": notes}


# PDF Generation (Finance report)
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
from fastapi.responses import StreamingResponse


@app.get("/reports/finance/pdf")
async def finance_pdf(
    division_id: Optional[str] = None,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    user: UserPublic = Depends(get_current_user)
):
    if db is None:
        raise HTTPException(status_code=500, detail="DB not configured")
    if user.role == "ADMIN_DIVISI":
        division_id = user.division_id

    # Fetch data
    summary = await finance_summary(division_id=division_id, date_from=date_from, date_to=date_to, user=user)  # type: ignore

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Header
    p.setFont("Helvetica-Bold", 14)
    p.drawString(40, height - 40, "PT Padud Jaya Putera")
    p.setFont("Helvetica", 12)
    p.drawString(40, height - 60, "Laporan Keuangan Ringkas")
    period = f"Periode: {(date_from or date.min).isoformat()} s/d {(date_to or date.max).isoformat()}"
    p.setFont("Helvetica", 10)
    p.drawString(40, height - 80, period)

    y = height - 120
    p.setFont("Helvetica-Bold", 12)
    p.drawString(40, y, "Ringkasan")
    y -= 20
    p.setFont("Helvetica", 10)
    p.drawString(50, y, f"Saldo Kas: {summary['cash']:.2f}")
    y -= 16
    p.drawString(50, y, f"Piutang - Baru: {summary['receivables']['baru']:.2f}")
    y -= 16
    p.drawString(50, y, f"Piutang - Tertagih: {summary['receivables']['tertagih']:.2f}")
    y -= 16
    p.drawString(50, y, f"Piutang - Macet: {summary['receivables']['macet']:.2f}")
    y -= 16
    p.drawString(50, y, f"Utang - Baru: {summary['payables']['baru']:.2f}")
    y -= 16
    p.drawString(50, y, f"Utang - Dibayar: {summary['payables']['dibayar']:.2f}")

    y -= 30
    p.setFont("Helvetica", 9)
    p.drawString(40, y, f"Dibuat pada: {datetime.now(timezone.utc).isoformat()}")

    p.showPage()
    p.save()
    buffer.seek(0)

    filename = "laporan_keuangan.pdf"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)


# Dashboard overview
@app.get("/dashboard/overview")
async def dashboard_overview(user: UserPublic = Depends(get_current_user)):
    if db is None:
        return {"stats": {}, "activity": []}
    if user.role == "ADMIN_DIVISI":
        raise HTTPException(status_code=403, detail="Super Admin only")
    stats = {
        "divisions": db["division"].count_documents({"is_active": True}),
        "users": db["user"].count_documents({"is_active": True}),
        "accounts": db["account"].count_documents({"is_active": True}),
        "cash_tx": db["cashentry"].count_documents({}),
    }
    activity = list(db["cashentry"].find({}).sort("created_at", -1).limit(20))
    for a in activity:
        a["_id"] = str(a["_id"])  # json safe
    return {"stats": stats, "activity": activity}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
