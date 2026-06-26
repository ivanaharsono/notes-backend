import os
import secrets
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

import psycopg2
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import bcrypt
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

# =========================================================================
# KONFIGURASI
# =========================================================================
DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
OTP_EXPIRE_MINUTES = 5

mail_conf = ConnectionConfig(
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
    MAIL_FROM=os.environ.get("MAIL_FROM", os.environ.get("MAIL_USERNAME", "noreply@example.com")),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", 587)),
    MAIL_SERVER=os.environ.get("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)
fm = FastMail(mail_conf)


# =========================================================================
# DATABASE HELPER
# =========================================================================
def get_db_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL belum disetting di Environment / Secrets!")
    return psycopg2.connect(DATABASE_URL)


def run_query(query, params=(), fetch=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        result = None
        if fetch == "one":
            result = cur.fetchone()
        elif fetch == "all":
            result = cur.fetchall()
        conn.commit()
        cur.close()
        return result
    finally:
        conn.close()


def init_db():
    if not DATABASE_URL:
        print("[WARN] DATABASE_URL kosong, init_db dilewati.")
        return
    run_query("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            is_verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    run_query("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id SERIAL PRIMARY KEY,
            email VARCHAR(150) NOT NULL,
            code VARCHAR(6) NOT NULL,
            purpose VARCHAR(20) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    run_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;")


# =========================================================================
# UTIL & SECURITY (BCRYPT DIRECT)
# =========================================================================
def hash_password(password: str) -> str:
    # Memastikan format UTF-8 dan memotong ke limit 72 byte agar tidak bentrok dengan aturan bcrypt
    password_bytes = password.encode('utf-8')[:72]
    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode('utf-8')[:72]
    return bcrypt.checkpw(plain_bytes, hashed_password.encode('utf-8'))

def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def save_otp(email: str, purpose: str) -> str:
    code = generate_otp()
    expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    run_query("DELETE FROM otp_codes WHERE email = %s AND purpose = %s", (email, purpose))
    run_query(
        "INSERT INTO otp_codes (email, code, purpose, expires_at) VALUES (%s, %s, %s, %s)",
        (email, code, purpose, expires),
    )
    return code


def verify_otp(email: str, code: str, purpose: str) -> bool:
    row = run_query(
        "SELECT expires_at FROM otp_codes WHERE email = %s AND code = %s AND purpose = %s",
        (email, code, purpose),
        fetch="one",
    )
    if not row:
        return False
    if row[0] < datetime.utcnow():
        run_query("DELETE FROM otp_codes WHERE email = %s AND purpose = %s", (email, purpose))
        return False
    run_query("DELETE FROM otp_codes WHERE email = %s AND purpose = %s", (email, purpose))
    return True


async def send_email(subject: str, recipients: list[str], html_body: str):
    message = MessageSchema(
        subject=subject,
        recipients=recipients,
        body=html_body,
        subtype=MessageType.html,
    )
    await fm.send_message(message)


# =========================================================================
# APP & MODELS
# =========================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Notes API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignupRequest(BaseModel):
    full_name: str
    email: EmailStr
    javaPassword: str

class LoginRequest(BaseModel):
    email: EmailStr
    javaPassword: str

class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    newPassword: str

class ChangePasswordRequest(BaseModel):
    email: EmailStr
    oldPassword: str
    newPassword: str

class FeedbackRequest(BaseModel):
    email: EmailStr
    message: str
    name: str | None = None


# =========================================================================
# ENDPOINTS
# =========================================================================
@app.get("/")
def root():
    return {"status": "ok", "message": "Notes API is running"}


@app.post("/signup")
async def signup(req: SignupRequest):
    try:
        existing = run_query(
            "SELECT is_verified FROM users WHERE email = %s", (req.email,), fetch="one"
        )
        if existing and existing[0] is True:
            return {"status": "error", "message": "Email sudah terdaftar!"}

        # Menggunakan helper manual untuk bypass error passlib
        hashed = hash_password(req.javaPassword)

        if existing:
            run_query(
                "UPDATE users SET full_name = %s, password = %s WHERE email = %s",
                (req.full_name, hashed, req.email),
            )
        else:
            run_query(
                "INSERT INTO users (full_name, email, password, is_verified) "
                "VALUES (%s, %s, %s, FALSE)",
                (req.full_name, req.email, hashed),
            )

        code = save_otp(req.email, "signup")
        await send_email(
            subject="Kode OTP Pendaftaran Notes",
            recipients=[req.email],
            html_body=f"""
                <h3>Halo {req.full_name},</h3>
                <p>Kode OTP pendaftaran kamu:</p>
                <h1 style="letter-spacing:4px;">{code}</h1>
                <p>Kode berlaku {OTP_EXPIRE_MINUTES} menit.</p>
            """,
        )
        return {"status": "success", "message": "OTP sudah dikirim ke email kamu."}

    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}


@app.post("/verify-otp")
def verify_signup(req: VerifyOtpRequest):
    try:
        if not verify_otp(req.email, req.otp, "signup"):
            return {"status": "error", "message": "OTP salah atau sudah kedaluwarsa."}
        run_query("UPDATE users SET is_verified = TRUE WHERE email = %s", (req.email,))
        return {"status": "success", "message": "Verifikasi berhasil! Akun aktif."}
    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}


@app.post("/login")
def login(req: LoginRequest):
    try:
        row = run_query(
            "SELECT password, is_verified FROM users WHERE email = %s",
            (req.email,),
            fetch="one",
        )
        if not row:
            return {"status": "error", "message": "Email atau Password salah!"}

        hashed, is_verified = row
        # Menggunakan helper manual
        if not verify_password(req.javaPassword, hashed):
            return {"status": "error", "message": "Email atau Password salah!"}
        if not is_verified:
            return {"status": "error", "message": "Akun belum diverifikasi. Cek email OTP."}

        return {"status": "success", "message": "Login berhasil!"}
    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}


@app.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    try:
        user = run_query(
            "SELECT full_name FROM users WHERE email = %s AND is_verified = TRUE",
            (req.email,),
            fetch="one",
        )
        generic = {"status": "success", "message": "Jika email terdaftar, OTP reset sudah dikirim."}
        if not user:
            return generic

        code = save_otp(req.email, "reset")
        await send_email(
            subject="Kode OTP Reset Password Notes",
            recipients=[req.email],
            html_body=f"""
                <h3>Halo {user[0]},</h3>
                <p>Kode OTP untuk reset password:</p>
                <h1 style="letter-spacing:4px;">{code}</h1>
                <p>Kode berlaku {OTP_EXPIRE_MINUTES} menit. Abaikan jika kamu tidak meminta ini.</p>
            """,
        )
        return generic
    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest):
    try:
        if not verify_otp(req.email, req.otp, "reset"):
            return {"status": "error", "message": "OTP salah atau sudah kedaluwarsa."}
        hashed = hash_password(req.newPassword)
        run_query("UPDATE users SET password = %s WHERE email = %s", (hashed, req.email))
        return {"status": "success", "message": "Password berhasil diubah."}
    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}


@app.post("/change-password")
def change_password(req: ChangePasswordRequest):
    try:
        row = run_query(
            "SELECT password FROM users WHERE email = %s AND is_verified = TRUE",
            (req.email,),
            fetch="one",
        )
        if not row:
            return {"status": "error", "message": "User tidak ditemukan."}
        if not verify_password(req.oldPassword, row[0]):
            return {"status": "error", "message": "Password lama salah!"}

        hashed = hash_password(req.newPassword)
        run_query("UPDATE users SET password = %s WHERE email = %s", (hashed, req.email))
        return {"status": "success", "message": "Password berhasil diubah."}
    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}


@app.post("/feedback")
async def feedback(req: FeedbackRequest):
    try:
        if not ADMIN_EMAIL:
            return {"status": "error", "message": "ADMIN_EMAIL belum disetting."}
        sender_name = req.name or "Anonim"
        await send_email(
            subject=f"[Feedback Notes] dari {sender_name}",
            recipients=[ADMIN_EMAIL],
            html_body=f"""
                <h3>Feedback baru</h3>
                <p><b>Nama:</b> {sender_name}</p>
                <p><b>Email:</b> {req.email}</p>
                <p><b>Pesan:</b></p>
                <p>{req.message}</p>
            """,
        )
        return {"status": "success", "message": "Feedback terkirim. Terima kasih!"}
    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}