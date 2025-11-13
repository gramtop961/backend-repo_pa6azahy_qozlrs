"""
Database Schemas for PT Padud Jaya Putera Accounting System

Each Pydantic model maps to a MongoDB collection: class name lowercased.
Example: User -> "user"
"""

from typing import Optional, Literal, List
from pydantic import BaseModel, Field, EmailStr
from datetime import date

# Core entities
class Division(BaseModel):
    name: str
    code: str = Field(..., description="Short unique code")
    is_active: bool = True

class User(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str
    role: Literal["SUPER_ADMIN", "ADMIN_DIVISI"]
    division_id: Optional[str] = Field(None, description="Only for ADMIN_DIVISI")
    is_active: bool = True

class Account(BaseModel):
    code: str = Field(..., description="COA code")
    name: str
    type: Literal["asset", "liability", "equity", "revenue", "expense"]
    is_active: bool = True

# Finance entries
class CashEntry(BaseModel):
    date: date
    division_id: str
    type: Literal["penerimaan", "pengeluaran"]
    account_code: str
    amount: float = Field(..., gt=0)
    description: Optional[str] = None

class ReceivableEntry(BaseModel):
    date: date
    division_id: str
    status: Literal["baru", "tertagih", "macet"]
    customer: str
    amount: float = Field(..., gt=0)
    description: Optional[str] = None

class PayableEntry(BaseModel):
    date: date
    division_id: str
    status: Literal["baru", "dibayar"]
    supplier: str
    amount: float = Field(..., gt=0)
    description: Optional[str] = None

class ActivityLog(BaseModel):
    actor_user_id: str
    action: str
    target_module: str
    payload_summary: Optional[str] = None

# Notification
class Notification(BaseModel):
    title: str
    message: str
    level: Literal["info", "success", "warning", "error"] = "info"
    audience: Literal["all", "division"] = "all"
    division_id: Optional[str] = None
