from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import bcrypt
import sqlite3
import random
import string
from typing import Optional

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
    """Initialize database and create users + temp_users + events tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'end-user'
        )
    ''')
    
    # Temporary users table for OTP verification
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temp_users (
            email TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            phone TEXT,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            otp TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            location TEXT NOT NULL,
            standard_price REAL NOT NULL,
            vip_price REAL NOT NULL,
            image_url TEXT,
            organizer_name TEXT NOT NULL,
            organizer_phone TEXT NOT NULL,
            organizer_email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("🗄️ Database tables created/verified")

def create_demo_users():
    """Create demo users automatically on startup"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if users already exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:  # No users exist
        hashed_password = bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode()
        
        users = [
            ("John Doe", "user@example.com", "+1234567890", hashed_password, "end-user"),
            ("Admin User", "admin@example.com", "+1987654321", hashed_password, "admin")
        ]
        
        cursor.executemany("INSERT INTO users (username, email, phone, password, role) VALUES (?, ?, ?, ?, ?)", users)
        conn.commit()
        print("✅ Demo users created:")
        print("   User: user@example.com / password123")
        print("   Admin: admin@example.com / password123")
    
    conn.close()

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

# Pydantic models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = "end-user"

class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    phone: str
    password: str
    role: str = "end-user"

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str

class EventRequest(BaseModel):
    title: str
    description: str
    category: str
    date: str
    time: str
    location: str
    standardPrice: float
    vipPrice: float
    imageUrl: Optional[str] = ""
    organizerName: str
    organizerPhone: str
    organizerEmail: str

# Login endpoint
@app.post("/login")
async def login(login_data: LoginRequest):
    try:
        print(f"🔍 Login attempt: {login_data.email} as {login_data.role}")
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (login_data.email,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            print(f"❌ User not found: {login_data.email}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        print(f"✅ User found: {user[1]} ({user[5]})")
        
        if not bcrypt.checkpw(login_data.password.encode(), user[4].encode()):
            print("❌ Password verification failed")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        if login_data.role != user[5]:
            print(f"❌ Role mismatch: requested {login_data.role}, user has {user[5]}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        return {
            "success": True,
            "message": f"Login successful as {user[5]}",
            "user": {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "phone": user[3],
                "role": user[5]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

# OTP endpoints
@app.post("/api/auth/send-otp")
async def send_otp(signup_data: SignupRequest):
    try:
        print(f"📧 Sending OTP to: {signup_data.email}")
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (signup_data.email,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Email already registered")
        
        otp = generate_otp()
        print(f"🔢 Generated OTP: {otp}")
        
        hashed_password = bcrypt.hashpw(signup_data.password.encode(), bcrypt.gensalt()).decode()
        
        cursor.execute("""
            INSERT OR REPLACE INTO temp_users (email, username, phone, password, role, otp) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (signup_data.email, signup_data.username, signup_data.phone, hashed_password, signup_data.role, otp))
        
        conn.commit()
        conn.close()
        
        print(f"✅ OTP stored for {signup_data.email}")
        
        return {
            "success": True,
            "message": "OTP sent successfully",
            "otp": otp
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Send OTP error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send OTP")

@app.post("/api/auth/verify-otp")
async def verify_otp(verify_data: OTPVerifyRequest):
    try:
        print(f"🔍 Verifying OTP for: {verify_data.email}")
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM temp_users WHERE email = ?", (verify_data.email,))
        temp_user = cursor.fetchone()
        
        if not temp_user:
            conn.close()
            raise HTTPException(status_code=400, detail="No signup found. Please sign up again.")
        
        if verify_data.otp != temp_user[5]:
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid OTP")
        
        print(f"✅ OTP verified for {verify_data.email}")
        
        cursor.execute("""
            INSERT INTO users (username, email, phone, password, role) 
            VALUES (?, ?, ?, ?, ?)
        """, (temp_user[1], temp_user[0], temp_user[2], temp_user[3], temp_user[4]))
        
        cursor.execute("DELETE FROM temp_users WHERE email = ?", (verify_data.email,))
        
        conn.commit()
        conn.close()
        
        print(f"✅ User account created: {verify_data.email}")
        
        return {
            "success": True,
            "message": f"Account created successfully as {temp_user[4]}",
            "user": {
                "username": temp_user[1],
                "email": temp_user[0],
                "phone": temp_user[2],
                "role": temp_user[4]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Verify OTP error: {e}")
        raise HTTPException(status_code=500, detail="OTP verification failed")

# EVENT ENDPOINTS
@app.post("/api/events")
async def create_event(event_data: EventRequest):
    """Create a new event"""
    try:
        print(f"🎪 Creating new event: {event_data.title}")
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO events (
                title, description, category, date, time, location,
                standard_price, vip_price, image_url, organizer_name, 
                organizer_phone, organizer_email
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data.title, event_data.description, event_data.category,
            event_data.date, event_data.time, event_data.location,
            event_data.standardPrice, event_data.vipPrice, event_data.imageUrl,
            event_data.organizerName, event_data.organizerPhone, event_data.organizerEmail
        ))
        
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"✅ Event created with ID: {event_id}")
        
        return {
            "success": True,
            "message": "Event created successfully",
            "event_id": event_id
        }
        
    except Exception as e:
        print(f"💥 Error creating event: {e}")
        raise HTTPException(status_code=500, detail="Failed to create event")

@app.get("/api/events")
async def get_events():
    """Get all events"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, title, description, category, date, time, location,
                   standard_price, vip_price, image_url, organizer_name,
                   organizer_phone, organizer_email
            FROM events 
            ORDER BY date ASC
        """)
        
        events = cursor.fetchall()
        conn.close()
        
        events_list = []
        for event in events:
            events_list.append({
                "id": event[0],
                "title": event[1],
                "description": event[2],
                "category": event[3],
                "date": event[4],
                "time": event[5],
                "location": event[6],
                "standardPrice": event[7],
                "vipPrice": event[8],
                "imageUrl": event[9] or "/default-event.jpg",
                "organizer": {
                    "name": event[10],
                    "phone": event[11],
                    "email": event[12]
                }
            })
        
        return {
            "success": True,
            "events": events_list
        }
        
    except Exception as e:
        print(f"💥 Error fetching events: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch events")

@app.get("/api/events/{event_id}")
async def get_event(event_id: int):
    """Get single event by ID"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, title, description, category, date, time, location,
                   standard_price, vip_price, image_url, organizer_name,
                   organizer_phone, organizer_email
            FROM events WHERE id = ?
        """, (event_id,))
        
        event = cursor.fetchone()
        conn.close()
        
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        
        return {
            "success": True,
            "event": {
                "id": event[0],
                "title": event[1],
                "description": event[2],
                "category": event[3],
                "date": event[4],
                "time": event[5],
                "location": event[6],
                "standardPrice": event[7],
                "vipPrice": event[8],
                "imageUrl": event[9] or "/default-event.jpg",
                "organizer": {
                    "name": event[10],
                    "phone": event[11],
                    "email": event[12]
                }
            }
        }
    except Exception as e:
        print(f"💥 Error fetching event: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch event")

# ADMIN EVENTS ENDPOINT - NEW (fixes the 404 error)
@app.get("/api/admin/events")
async def get_admin_events():
    """Get all events for admin management"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, title, description, category, date, time, location,
                   standard_price, vip_price, image_url, organizer_name,
                   organizer_phone, organizer_email, created_at
            FROM events 
            ORDER BY created_at DESC
        """)
        
        events = cursor.fetchall()
        conn.close()
        
        events_list = []
        for event in events:
            events_list.append({
                "id": event[0],
                "title": event[1],
                "description": event[2],
                "category": event[3],
                "date": event[4],
                "time": event[5],
                "location": event[6],
                "standardPrice": event[7],
                "vipPrice": event[8],
                "imageUrl": event[9] or "/default-event.jpg",
                "organizer": {
                    "name": event[10],
                    "phone": event[11],
                    "email": event[12]
                },
                "createdAt": event[13]
            })
        
        return {
            "success": True,
            "events": events_list
        }
        
    except Exception as e:
        print(f"💥 Error fetching admin events: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch admin events")

@app.on_event("startup")
async def startup():
    """Initialize database and create demo users on startup"""
    init_db()
    create_demo_users()
    print("✅ API Ready - Login, OTP Signup & Event Creation enabled!")

@app.get("/")
async def root():
    return {"message": "Event Booking API with SQLite3 + OTP Signup + Event Creation - Ready!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
