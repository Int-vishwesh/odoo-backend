from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import bcrypt
import sqlite3

app = FastAPI()

# CORS for your Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite database file
DATABASE = "users.db"

def init_db():
    """Initialize database and create users table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'end-user'
        )
    ''')
    conn.commit()
    conn.close()

def create_demo_users():
    """Create demo users automatically on startup"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if users already exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:  # No users exist
        hashed_password = bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode()
        
        users = [
            ("John Doe", "user@example.com", hashed_password, "end-user"),
            ("Admin User", "admin@example.com", hashed_password, "admin")
        ]
        
        cursor.executemany("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", users)
        conn.commit()
        print("✅ Demo users created:")
        print("   User: user@example.com / password123")
        print("   Admin: admin@example.com / password123")
    
    conn.close()

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = "end-user"

@app.post("/login")
async def login(login_data: LoginRequest):
    try:
        print(f"🔍 Login attempt: {login_data.email} as {login_data.role}")
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Find user by email
        cursor.execute("SELECT * FROM users WHERE email = ?", (login_data.email,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            print(f"❌ User not found: {login_data.email}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        print(f"✅ User found: {user[1]} ({user[4]})")
        
        # Verify password
        if not bcrypt.checkpw(login_data.password.encode(), user[3].encode()):
            print("❌ Password verification failed")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        print("✅ Password verified")
        
        # Check role matches what user selected
        if login_data.role != user[4]:
            print(f"❌ Role mismatch: requested {login_data.role}, user has {user[4]}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        print("✅ Role verified")
        
        # Return success response
        return {
            "success": True,
            "message": f"Login successful as {user[4]}",
            "user": {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[4]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

# Add missing API routes that your frontend is looking for
@app.get("/api/events")
async def get_events():
    """Placeholder for events API"""
    return {
        "success": True,
        "events": [
            {"id": 1, "title": "Sample Event 1", "date": "2025-09-01"},
            {"id": 2, "title": "Sample Event 2", "date": "2025-09-15"}
        ]
    }

@app.get("/api/events/{event_id}")
async def get_event(event_id: int):
    """Placeholder for single event API"""
    return {
        "success": True,
        "event": {"id": event_id, "title": f"Event {event_id}", "date": "2025-09-01"}
    }

@app.on_event("startup")
async def startup():
    """Initialize database and create demo users on startup"""
    init_db()
    create_demo_users()

@app.get("/")
async def root():
    return {"message": "Event Booking API with SQLite3 - Ready for login testing!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
