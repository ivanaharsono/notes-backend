from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import os

app = FastAPI()

# 🛡️ Biar API lu kaga diblokir (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🔗 Ambil kunci rahasia Neon dari pengaturan Hugging Face
DATABASE_URL = os.environ.get("DATABASE_URL")

# 📦 Format paket dari Android lu (Harus SAMA PERSIS hurufnya)
class AuthRequest(BaseModel):
    email: str
    javaPassword: str

# 🚀 Fungsi Connect ke Neon
def get_db_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL belum disetting di Hugging Face!")
    return psycopg2.connect(DATABASE_URL)

# ---------------------------------------------------------
# 🚪 ENDPOINT SIGN UP
# ---------------------------------------------------------
@app.post("/signup")
def signup(request: AuthRequest):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Cek apakah email udah ada
        cursor.execute("SELECT email FROM users WHERE email = %s", (request.email,))
        if cursor.fetchone():
            return {"status": "error", "message": "Email sudah terdaftar!"}

        # Masukin ke database Neon
        cursor.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)", 
            (request.email, request.javaPassword)
        )
        conn.commit()
        
        cursor.close()
        conn.close()
        return {"status": "success", "message": "Sign up berhasil!"}

    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}

# ---------------------------------------------------------
# 🚪 ENDPOINT LOGIN
# ---------------------------------------------------------
@app.post("/login")
def login(request: AuthRequest):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Cari email dan password yang cocok di Neon
        cursor.execute(
            "SELECT email FROM users WHERE email = %s AND password = %s", 
            (request.email, request.javaPassword)
        )
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()

        if user:
            return {"status": "success", "message": "Login berhasil!"}
        else:
            return {"status": "error", "message": "Email atau Password salah!"}

    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}