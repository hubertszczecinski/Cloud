from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Form, Response, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, func, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from typing import List, Optional
import os
import hashlib
import secrets
import logging
import jwt
from jwt.exceptions import InvalidTokenError

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Konfiguracja JWT
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable is required!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security
security = HTTPBearer()

# Database
def get_base_dir():
    if os.path.exists('/home/site'):
        return '/home/site/wwwroot'
    else:
        return os.getcwd()

BASE_DIR = get_base_dir()
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'file_exchange.db')}"

logger.info(f"Using BASE_DIR: {BASE_DIR}")
logger.info(f"Using DATABASE_URL: {DATABASE_URL}")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    api_key = Column(String, unique=True, index=True)  # Zachowujemy dla kompatybilności
    permissions = Column(String, default="read,write")
    created_at = Column(DateTime, default=func.now())

class FileMetadata(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    size = Column(Integer)
    version = Column(Integer, default=1)
    upload_date = Column(DateTime, default=func.now())
    uploaded_by = Column(String)
    owner_username = Column(String)
    file_path = Column(String)

class LogEntry(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    action = Column(String)
    filename = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=func.now())

# Setup database
def setup_database():
    try:
        uploads_dir = os.path.join(BASE_DIR, 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        logger.info(f"Created uploads directory: {uploads_dir}")
        
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        required_tables = ['users', 'files', 'logs']
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            logger.info(f"Creating missing tables: {missing_tables}")
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created successfully")
        else:
            logger.info("All database tables already exist")
            
    except Exception as e:
        logger.error(f"Database setup error: {str(e)}")
        raise

setup_database()

app = FastAPI(title="File Exchange System")

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions dla JWT
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except InvalidTokenError:
        return None

# Nowa dependency dla JWT
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db = Depends(get_db)
):
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def log_action(db, username: str, action: str, filename: Optional[str] = None, details: Optional[str] = None):
    log_entry = LogEntry(
        username=username,
        action=action,
        filename=filename,
        details=details
    )
    db.add(log_entry)
    db.commit()

def save_file_locally(filename: str, content: bytes, username: str) -> str:
    user_folder = os.path.join(BASE_DIR, 'uploads', username)
    os.makedirs(user_folder, exist_ok=True)
    file_path = os.path.join(user_folder, filename)
    with open(file_path, "wb") as f:
        f.write(content)
    return file_path

# Auth endpoints z JWT
@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), db = Depends(get_db)):
    try:
        logger.info(f"Registration attempt for user: {username}")
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password are required")
        
        if len(username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
        
        if len(password) < 4:
            raise HTTPException(status_code=400, detail="Password must be at least 4 characters long")
        
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        api_key = generate_api_key()
        user = User(
            username=username, 
            password_hash=hash_password(password), 
            api_key=api_key
        )
        db.add(user)
        db.commit()
        
        log_action(db, username, "register", details="User registered")
        logger.info(f"User {username} registered successfully")
        
        return {
            "message": "User registered successfully", 
            "success": True
        }
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...), db = Depends(get_db)):
    try:
        logger.info(f"Login attempt for user: {username}")
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password are required")
        
        user = db.query(User).filter(User.username == username).first()
        if not user or user.password_hash != hash_password(password):
            logger.warning(f"Invalid credentials for user: {username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Tworzymy JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        log_action(db, username, "login", details="User logged in with JWT")
        logger.info(f"User {username} logged in successfully")
        
        return {
            "message": "Login successful", 
            "access_token": access_token,
            "token_type": "bearer",
            "success": True
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db = Depends(get_db)):
    try:
        log_action(db, current_user.username, "logout", details="User logged out")
        logger.info(f"User {current_user.username} logged out")
        
        return {"message": "Successfully logged out", "success": True}
    
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return {"message": "Logout completed", "success": True}

# File operations z JWT
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    try:
        contents = await file.read()
        
        existing = db.query(FileMetadata).filter(
            FileMetadata.filename == file.filename,
            FileMetadata.owner_username == current_user.username
        ).first()
        
        version = existing.version + 1 if existing else 1
        file_path = save_file_locally(file.filename, contents, current_user.username)
        
        if existing:
            existing.version = version
            existing.size = len(contents)
            existing.upload_date = datetime.now()
            existing.file_path = file_path
        else:
            metadata = FileMetadata(
                filename=file.filename, 
                size=len(contents), 
                version=version,
                uploaded_by=current_user.username,
                owner_username=current_user.username,
                file_path=file_path
            )
            db.add(metadata)
        
        db.commit()
        log_action(db, current_user.username, "upload", file.filename, f"Version {version}")
        
        return {
            "message": f"File {file.filename} uploaded successfully",
            "version": version, 
            "size": len(contents), 
            "success": True
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.post("/upload-multiple")
async def upload_multiple(
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    try:
        results = []
        
        for file in files:
            contents = await file.read()
            file_path = save_file_locally(file.filename, contents, current_user.username)
            
            existing = db.query(FileMetadata).filter(
                FileMetadata.filename == file.filename,
                FileMetadata.owner_username == current_user.username
            ).first()
            
            version = existing.version + 1 if existing else 1
            
            if existing:
                existing.version = version
                existing.size = len(contents)
                existing.upload_date = datetime.now()
                existing.file_path = file_path
            else:
                metadata = FileMetadata(
                    filename=file.filename, 
                    size=len(contents), 
                    version=version,
                    uploaded_by=current_user.username,
                    owner_username=current_user.username,
                    file_path=file_path
                )
                db.add(metadata)
            
            results.append(f"Uploaded {file.filename} (v{version})")
        
        db.commit()
        log_action(db, current_user.username, "upload_multiple", details=f"Uploaded {len(files)} files")
        
        return {"message": f"Uploaded {len(files)} files", "details": results, "success": True}
    
    except Exception as e:
        db.rollback()
        logger.error(f"Upload multiple error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/files")
async def list_files(current_user: User = Depends(get_current_user), db = Depends(get_db)):
    try:
        files = db.query(FileMetadata).filter(
            FileMetadata.owner_username == current_user.username
        ).all()
        
        log_action(db, current_user.username, "list_files")
        return {
            "files": [
                {
                    "filename": f.filename,
                    "size": f.size,
                    "version": f.version,
                    "upload_date": f.upload_date.isoformat(),
                    "uploaded_by": f.uploaded_by
                } for f in files
            ],
            "success": True
        }
    
    except Exception as e:
        logger.error(f"List files error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")

@app.get("/download/{filename}")
async def download_file(filename: str, current_user: User = Depends(get_current_user), db = Depends(get_db)):
    try:
        file_meta = db.query(FileMetadata).filter(
            FileMetadata.filename == filename,
            FileMetadata.owner_username == current_user.username
        ).first()
        
        if not file_meta:
            raise HTTPException(status_code=404, detail="File not found or access denied")
        
        if not os.path.exists(file_meta.file_path):
            raise HTTPException(status_code=404, detail="File not found on server")
        
        log_action(db, current_user.username, "download", filename)
        
        return FileResponse(
            path=file_meta.file_path,
            filename=filename,
            media_type='application/octet-stream'
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")

@app.get("/logs")
async def get_logs(current_user: User = Depends(get_current_user), db = Depends(get_db)):
    try:
        logs = db.query(LogEntry).filter(
            LogEntry.username == current_user.username
        ).order_by(LogEntry.timestamp.desc()).limit(100).all()
        
        return {
            "logs": [{
                "username": l.username,
                "action": l.action,
                "filename": l.filename,
                "details": l.details,
                "timestamp": l.timestamp.isoformat()
            } for l in logs],
            "success": True
        }
    
    except Exception as e:
        logger.error(f"Get logs error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get logs: {str(e)}")

# HTML Interface z obsługą JWT
@app.get("/", response_class=HTMLResponse)
async def read_root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Exchange System</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            button { padding: 10px 15px; margin: 5px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 5px; }
            button:hover { background: #0056b3; }
            .btn-download { background: #28a745; }
            .btn-download:hover { background: #218838; }
            .btn-logout { background: #dc3545; }
            .btn-logout:hover { background: #c82333; }
            input, select { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; width: 200px; }
            .hidden { display: none; }
            .success { color: green; padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; }
            .error { color: red; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; }
            .file-item { border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 4px; }
            .user-info { background: #e9ecef; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
            .token-info { background: #d1ecf1; padding: 10px; border-radius: 5px; margin: 10px 0; font-size: 12px; word-break: break-all; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📁 File Exchange System (JWT)</h1>
            
            <div id="loginSection" class="section">
                <h2>Login / Register</h2>
                <input type="text" id="username" placeholder="Username">
                <input type="password" id="password" placeholder="Password">
                <br>
                <button onclick="login()">Login</button>
                <button onclick="register()">Register</button>
                <div id="authResult"></div>
            </div>
            
            <div id="appSection" class="section hidden">
                <div class="user-info">
                    <h2>Welcome, <span id="userName"></span>!</h2>
                    <p><strong>Your private file space</strong></p>
                </div>
                <div class="token-info">
                    <strong>User Token</strong> - expires in 30 minutes
                </div>
                <button class="btn-logout" onclick="logout()">Logout</button>
                
                <h3>Operations:</h3>
                <button onclick="showSection('uploadSection')">Upload File</button>
                <button onclick="showSection('multiUploadSection')">Upload Multiple</button>
                <button onclick="showSection('filesSection')">My Files</button>
                <button onclick="showSection('logsSection')">My Activity Logs</button>
                
                <div id="uploadSection" class="section hidden">
                    <h3>Upload Single File</h3>
                    <input type="file" id="singleFile">
                    <button onclick="uploadFile()">Upload</button>
                    <div id="uploadResult"></div>
                </div>
                
                <div id="multiUploadSection" class="section hidden">
                    <h3>Upload Multiple Files</h3>
                    <input type="file" id="multipleFiles" multiple>
                    <button onclick="uploadMultiple()">Upload All</button>
                    <div id="multiUploadResult"></div>
                </div>
                
                <div id="filesSection" class="section hidden">
                    <h3>My Files</h3>
                    <button onclick="loadFiles()">Refresh My Files</button>
                    <div id="filesList"></div>
                </div>
                
                <div id="logsSection" class="section hidden">
                    <h3>My Activity Logs</h3>
                    <button onclick="loadLogs()">Refresh My Logs</button>
                    <div id="logsList"></div>
                </div>
            </div>
        </div>
        
        <script>
            let accessToken = '';
            let currentUser = '';
            
            function showSection(sectionId) {
                document.querySelectorAll('.section').forEach(section => {
                    if (section.id !== 'appSection' && section.id !== 'loginSection') {
                        section.classList.add('hidden');
                    }
                });
                document.getElementById(sectionId).classList.remove('hidden');
            }
            
            async function apiCall(url, options = {}) {
                try {
                    const headers = {
                        ...options.headers
                    };
                    
                    if (accessToken) {
                        headers['Authorization'] = `Bearer ${accessToken}`;
                    }
                    
                    const requestOptions = {
                        ...options,
                        headers: headers
                    };
                    
                    const response = await fetch(url, requestOptions);
                    if (!response.ok) {
                        const errorText = await response.text();
                        let errorJson;
                        try {
                            errorJson = JSON.parse(errorText);
                        } catch {
                            throw new Error(errorText || 'Request failed');
                        }
                        throw new Error(errorJson.detail || errorJson.message || 'Request failed');
                    }
                    return await response.json();
                } catch (error) {
                    console.error('API Call error:', error);
                    if (error.message.includes('token') || error.message.includes('expired') || error.message.includes('Unauthorized')) {
                        logout();
                    }
                    throw error;
                }
            }
            
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                console.log('Login attempt for:', username); // ✅ Debug
                
                if (!username || !password) {
                    showMessage('authResult', 'Please enter username and password', 'error');
                    return;
                }
                
                const formData = new FormData();
                formData.append('username', username);
                formData.append('password', password);
                
                try {
                    const result = await apiCall('/login', { 
                        method: 'POST', 
                        body: formData 
                    });
                    
                    console.log('Login response:', result);
                    
                    if (result.success && result.access_token) {
                        accessToken = result.access_token;
                        currentUser = username;
                        
                        console.log('Setting accessToken:', accessToken);
                        console.log('Setting currentUser:', currentUser);
                        
                        const userNameElement = document.getElementById('userName');
                        const loginSection = document.getElementById('loginSection');
                        const appSection = document.getElementById('appSection');
                        
                        if (userNameElement && loginSection && appSection) {
                            userNameElement.textContent = username;
                            loginSection.classList.add('hidden');
                            appSection.classList.remove('hidden');
                            showMessage('authResult', 'Login successful!', 'success');
                            
                            // Automatycznie pokaż listę plików
                            showSection('filesSection');
                            loadFiles();
                        } else {
                            console.error('HTML elements not found!');
                            showMessage('authResult', 'Page error - elements missing', 'error');
                        }
                    } else {
                        showMessage('authResult', 'Login failed: No token received', 'error');
                    }
                } catch (error) {
                    console.error('Login error:', error);
                    showMessage('authResult', 'Login failed: ' + error.message, 'error');
                }
            }
            
            async function register() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                if (!username || !password) {
                    showMessage('authResult', 'Please enter username and password', 'error');
                    return;
                }
                
                if (username.length < 3) {
                    showMessage('authResult', 'Username must be at least 3 characters long', 'error');
                    return;
                }
                
                if (password.length < 4) {
                    showMessage('authResult', 'Password must be at least 4 characters long', 'error');
                    return;
                }
                
                const formData = new FormData();
                formData.append('username', username);
                formData.append('password', password);
                
                try {
                    const result = await apiCall('/register', { method: 'POST', body: formData });
                    if (result.success) {
                        showMessage('authResult', 'Registration successful! Please login.', 'success');
                        document.getElementById('username').value = '';
                        document.getElementById('password').value = '';
                    }
                } catch (error) {
                    showMessage('authResult', 'Registration failed: ' + error.message, 'error');
                }
            }
            
            async function logout() {
                try {
                    await apiCall('/logout', { method: 'POST' });
                } catch (error) {
                    // Ignore logout errors
                } finally {
                    accessToken = '';
                    currentUser = '';
                    document.getElementById('appSection').classList.add('hidden');
                    document.getElementById('loginSection').classList.remove('hidden');
                    document.getElementById('username').value = '';
                    document.getElementById('password').value = '';
                    showMessage('authResult', 'Logged out successfully!', 'success');
                }
            }
            
            function showMessage(elementId, message, type) {
                const element = document.getElementById(elementId);
                element.innerHTML = message;
                element.className = type;
            }
            
            async function uploadFile() {
                const fileInput = document.getElementById('singleFile');
                if (!fileInput.files[0]) {
                    showMessage('uploadResult', 'Please select a file', 'error');
                    return;
                }
                
                const formData = new FormData();
                formData.append('file', fileInput.files[0]);
                
                try {
                    const result = await apiCall('/upload', { method: 'POST', body: formData });
                    if (result.success) {
                        showMessage('uploadResult', `Success: ${result.message} (Version ${result.version})`, 'success');
                        fileInput.value = '';
                    }
                } catch (error) {
                    showMessage('uploadResult', 'Upload failed: ' + error.message, 'error');
                }
            }
            
            async function uploadMultiple() {
                const fileInput = document.getElementById('multipleFiles');
                if (!fileInput.files.length) {
                    showMessage('multiUploadResult', 'Please select files', 'error');
                    return;
                }
                
                const formData = new FormData();
                for (let file of fileInput.files) {
                    formData.append('files', file);
                }
                
                try {
                    const result = await apiCall('/upload-multiple', { method: 'POST', body: formData });
                    if (result.success) {
                        let message = `Success: ${result.message}`;
                        if (result.details) message += '<br>' + result.details.join('<br>');
                        showMessage('multiUploadResult', message, 'success');
                        fileInput.value = '';
                    }
                } catch (error) {
                    showMessage('multiUploadResult', 'Upload failed: ' + error.message, 'error');
                }
            }
            
            function downloadFile(filename) {
                window.open(`/download/${filename}`, '_blank');
            }
            
            async function loadFiles() {
                try {
                    const result = await apiCall('/files');
                    if (result.success) {
                        const filesList = document.getElementById('filesList');
                        filesList.innerHTML = '<h4>My Files:</h4>';
                        
                        if (result.files.length === 0) {
                            filesList.innerHTML += '<p>No files found. Upload your first file!</p>';
                            return;
                        }
                        
                        result.files.forEach(file => {
                            filesList.innerHTML += `
                                <div class="file-item">
                                    <strong>${file.filename}</strong><br>
                                    Size: ${file.size} bytes | Version: ${file.version}<br>
                                    Uploaded: ${new Date(file.upload_date).toLocaleString()}
                                    <br>
                                    <button class="btn-download" onclick="downloadFile('${file.filename}')">Download</button>
                                </div>
                            `;
                        });
                    }
                } catch (error) {
                    document.getElementById('filesList').innerHTML = 'Error loading files: ' + error.message;
                }
            }
            
            async function loadLogs() {
                try {
                    const result = await apiCall('/logs');
                    if (result.success) {
                        const logsList = document.getElementById('logsList');
                        logsList.innerHTML = '<h4>My Activity Logs:</h4>';
                        
                        if (result.logs.length === 0) {
                            logsList.innerHTML += '<p>No activity logs found</p>';
                            return;
                        }
                        
                        result.logs.forEach(log => {
                            logsList.innerHTML += `
                                <div class="file-item">
                                    <strong>${new Date(log.timestamp).toLocaleString()}</strong><br>
                                    Action: ${log.action}<br>
                                    ${log.filename ? 'File: ' + log.filename + '<br>' : ''}
                                    ${log.details ? 'Details: ' + log.details : ''}
                                </div>
                            `;
                        });
                    }
                } catch (error) {
                    document.getElementById('logsList').innerHTML = 'Error loading logs: ' + error.message;
                }
            }
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)