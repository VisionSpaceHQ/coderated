# CodeRated API Server - Integrated with Worker System
# Production-ready API server with task queues and background processing

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict
import asyncio
import json
from datetime import datetime, timedelta
import uuid
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
from passlib.context import CryptContext
import redis
from contextlib import asynccontextmanager
from fastapi import WebSocket
import os

# Import our CodeRated modules
from coderated_backend import CodeRatedAnalyzer, EmailOutreachManager, CampaignManager, run_single_analysis
from worker import TaskQueue  # Import the worker task queue
from monitor import CodeRatedMonitor, MetricsStorage  # Import monitoring
from auth_security import verify_password, get_password_hash, create_access_token, get_current_user, get_admin_user

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize task queue and monitoring
task_queue = TaskQueue()
metrics_storage = MetricsStorage()

# Initialize FastAPI app
app = FastAPI(
    title="CodeRated API",
    description="AI-Powered Website Intelligence and Review Platform with Worker System",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"

# Redis for caching and task queue
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'database': os.getenv('DB_NAME', 'coderated'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD')
}

# Make database optional for development
try:
    test_conn = psycopg2.connect(**DB_CONFIG)
    test_conn.close()
    DATABASE_AVAILABLE = True
    print("✅ Database connection successful")
except Exception as e:
    print(f"⚠️  Database not available: {e}")
    DATABASE_AVAILABLE = False

# Make Redis optional
try:
    redis_client.ping()
    REDIS_AVAILABLE = True
    print("✅ Redis connection successful")
except Exception as e:
    print(f"⚠️  Redis not available: {e}")
    REDIS_AVAILABLE = False
    redis_client = None

# Pydantic models
class AnalysisRequest(BaseModel):
    url: str
    priority: Optional[str] = "normal"  # normal, high, urgent
    auto_outreach: Optional[bool] = False

class CampaignRequest(BaseModel):
    name: str
    search_terms: List[str]
    max_sites: int = 100
    score_threshold: int = 75
    email_enabled: bool = True
    industry_filter: Optional[List[str]] = None

class UserRegistration(BaseModel):
    email: EmailStr
    name: str
    password: str
    tier: Optional[str] = "observer"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OutreachEmail(BaseModel):
    to_email: EmailStr
    template_type: str = "opportunity"
    custom_message: Optional[str] = None

class OutreachBatch(BaseModel):
    leads: List[Dict]
    template_type: str = "opportunity"

class TaskStatusRequest(BaseModel):
    task_id: str

class WebsiteAnalysisResponse(BaseModel):
    id: int
    url: str
    domain: str
    title: str
    score: int
    ux_design: int
    seo_fundamentals: int
    speed_optimization: int
    visual_identity: int
    strategic_copy: int
    industry: str
    contact_email: Optional[str]
    company_name: str
    analysis_summary: Dict
    created_at: datetime

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        if not DATABASE_AVAILABLE:
            # Mock user for development
            return {"id": 1, "email": email, "tier": "business"}
        
        # Get user from database
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return dict(user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get('tier') not in ['admin', 'business']:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# API Routes

@app.get("/")
async def root():
    return {"message": "CodeRated API v1.0 with Worker System", "status": "active"}

@app.get("/health")
async def health_check():
    """Enhanced health check endpoint with worker status"""
    services = {"api": "connected"}
    
    if DATABASE_AVAILABLE:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            services["database"] = "connected"
        except:
            services["database"] = "error"
    else:
        services["database"] = "not_configured"
    
    if REDIS_AVAILABLE and redis_client:
        try:
            redis_client.ping()
            services["redis"] = "connected"
            
            # Check worker health
            worker_health = redis_client.get('worker:health')
            if worker_health:
                worker_data = json.loads(worker_health)
                services["worker"] = worker_data.get('worker_status', 'unknown')
            else:
                services["worker"] = "not_running"
                
        except:
            services["redis"] = "error"
            services["worker"] = "unknown"
    else:
        services["redis"] = "not_configured"
        services["worker"] = "not_configured"
    
    services["ai_analyzer"] = "ready"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": services
    }

@app.get("/system/status")
async def get_system_status():
    """Get comprehensive system status including queues and metrics"""
    try:
        status = {
            "timestamp": datetime.now().isoformat(),
            "services": {
                "database": DATABASE_AVAILABLE,
                "redis": REDIS_AVAILABLE,
                "worker": False,
                "monitor": False
            },
            "queues": {},
            "metrics": {}
        }
        
        if REDIS_AVAILABLE:
            # Get queue lengths
            queue_names = ['analysis_urgent', 'analysis_normal', 'analysis_batch', 'outreach', 'campaign', 'cleanup']
            for queue_name in queue_names:
                queue_key = f"queue:{queue_name}"
                length = redis_client.zcard(queue_key)
                status["queues"][queue_name] = length
            
            # Check worker status
            worker_health = redis_client.get('worker:health')
            if worker_health:
                status["services"]["worker"] = True
                worker_data = json.loads(worker_health)
                status["worker_details"] = worker_data
            
            # Get latest metrics if available
            latest_metrics = await metrics_storage.get_latest_metrics()
            status["metrics"] = latest_metrics
            
            if latest_metrics:
                status["services"]["monitor"] = True
        
        return status
        
    except Exception as e:
        logger.error(f"Failed to get system status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system status")

# Authentication endpoints (same as before)
@app.post("/auth/register")
async def register_user(user: UserRegistration):
    """Register a new user"""
    if not DATABASE_AVAILABLE:
        # Mock registration for development
        return {
            "access_token": create_access_token({"sub": user.email}, timedelta(days=30)),
            "token_type": "bearer",
            "user_id": 1,
            "tier": user.tier,
            "api_key": "dev-api-key"
        }
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Check if user already exists
        cur.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password and create user
        hashed_password = get_password_hash(user.password)
        api_key = str(uuid.uuid4())
        
        cur.execute("""
            INSERT INTO users (email, name, password_hash, tier, api_key, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (user.email, user.name, hashed_password, user.tier, api_key, datetime.now()))
        
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user.email}, 
            expires_delta=timedelta(days=30)
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user_id,
            "tier": user.tier,
            "api_key": api_key
        }
        
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/auth/login")
async def login_user(user: UserLogin):
    """Login user"""
    if not DATABASE_AVAILABLE:
        # Mock login for development
        return {
            "access_token": create_access_token({"sub": user.email}, timedelta(days=30)),
            "token_type": "bearer",
            "user": {
                "id": 1,
                "email": user.email,
                "name": "Dev User",
                "tier": "business"
            }
        }
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT * FROM users WHERE email = %s", (user.email,))
        db_user = cur.fetchone()
        
        if not db_user or not verify_password(user.password, db_user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        cur.execute("UPDATE users SET last_login = %s WHERE id = %s", 
                   (datetime.now(), db_user['id']))
        conn.commit()
        cur.close()
        conn.close()
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user.email},
            expires_delta=timedelta(days=30)
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": db_user['id'],
                "email": db_user['email'],
                "name": db_user['name'],
                "tier": db_user['tier']
            }
        }
        
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

# Enhanced Analysis endpoints with Worker Integration
@app.post("/analyze", response_model=dict)
async def analyze_website(
    request: AnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """Analyze a website using worker system"""
    
    # Check user tier permissions
    if current_user['tier'] == 'observer':
        daily_limit = await check_daily_analysis_limit(current_user['id'])
        if daily_limit >= 5:  # Free tier limit
            raise HTTPException(status_code=403, detail="Daily analysis limit exceeded. Upgrade to continue.")
    
    try:
        # Check if analysis exists in cache
        cache_key = f"analysis:{request.url}"
        if REDIS_AVAILABLE:
            cached_result = redis_client.get(cache_key)
            if cached_result and request.priority == "normal":
                logger.info(f"Returning cached analysis for {request.url}")
                return json.loads(cached_result)
        
        # Queue or run analysis based on priority and system availability
        if request.priority == "urgent" or not REDIS_AVAILABLE:
            # Run immediately for urgent priority or if no Redis
            analysis = await run_single_analysis(request.url)
            result = format_analysis_response(analysis)
            
            # Cache result if Redis available
            if REDIS_AVAILABLE:
                redis_client.setex(cache_key, 3600, json.dumps(result))
        else:
            # Queue the task for background processing
            if not REDIS_AVAILABLE:
                raise HTTPException(status_code=503, detail="Worker system not available")
            
            # Determine queue based on priority
            queue_name = {
                "urgent": "analysis_urgent",
                "high": "analysis_normal", 
                "normal": "analysis_normal"
            }.get(request.priority, "analysis_normal")
            
            # Add task to queue
            task_id = await task_queue.add_task(queue_name, {
                'url': request.url,
                'user_id': current_user['id'],
                'priority': request.priority,
                'auto_outreach': request.auto_outreach
            })
            
            if not task_id:
                raise HTTPException(status_code=500, detail="Failed to queue analysis task")
            
            result = {
                "status": "queued",
                "task_id": task_id,
                "message": f"Analysis queued for {request.url}",
                "estimated_completion": (datetime.now() + timedelta(minutes=5)).isoformat(),
                "check_status_url": f"/tasks/{task_id}/status"
            }
        
        return result
        
    except Exception as e:
        logger.error(f"Analysis failed for {request.url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/tasks/{task_id}/status")
async def get_task_status(task_id: str):
    """Get status of a queued task"""
    if not REDIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Task system not available")
    
    try:
        # Check if task is completed
        completed_key = f"completed:{task_id}"
        completed_data = redis_client.get(completed_key)
        
        if completed_data:
            return {
                "status": "completed",
                "task_id": task_id,
                "completed_at": json.loads(completed_data).get('completed_at'),
                "message": "Task completed successfully"
            }
        
        # Check if task is failed
        failed_key = f"failed:{task_id}"
        failed_data = redis_client.get(failed_key)
        
        if failed_data:
            failed_info = json.loads(failed_data)
            return {
                "status": "failed",
                "task_id": task_id,
                "error": failed_info.get('last_error'),
                "retries": failed_info.get('retries', 0),
                "failed_at": failed_info.get('failed_at')
            }
        
        # Check if task is processing
        processing_key = f"processing:{task_id}"
        processing_data = redis_client.get(processing_key)
        
        if processing_data:
            return {
                "status": "processing",
                "task_id": task_id,
                "message": "Task is currently being processed"
            }
        
        # Check if task is still in queue
        for queue_name in ['analysis_urgent', 'analysis_normal', 'analysis_batch']:
            queue_key = f"queue:{queue_name}"
            tasks = redis_client.zrange(queue_key, 0, -1)
            for task_json in tasks:
                task = json.loads(task_json)
                if task['id'] == task_id:
                    return {
                        "status": "queued",
                        "task_id": task_id,
                        "queue": queue_name,
                        "created_at": task['created_at'],
                        "message": "Task is queued for processing"
                    }
        
        # Task not found
        raise HTTPException(status_code=404, detail="Task not found")
        
    except Exception as e:
        logger.error(f"Failed to get task status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve task status")

@app.get("/tasks/queue/status")
async def get_queue_status(current_user: dict = Depends(get_current_user)):
    """Get status of all task queues"""
    if not REDIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Task system not available")
    
    try:
        queue_status = {}
        queue_names = ['analysis_urgent', 'analysis_normal', 'analysis_batch', 'outreach', 'campaign', 'cleanup']
        
        for queue_name in queue_names:
            queue_key = f"queue:{queue_name}"
            length = redis_client.zcard(queue_key)
            queue_status[queue_name] = {
                "length": length,
                "queue_key": queue_key
            }
        
        # Get processing tasks count
        processing_keys = redis_client.keys("processing:*")
        total_processing = len(processing_keys)
        
        # Get completed tasks count (today)
        completed_keys = redis_client.keys("completed:*")
        completed_today = 0
        for key in completed_keys:
            task_data = redis_client.get(key)
            if task_data:
                try:
                    task = json.loads(task_data)
                    completed_time = datetime.fromisoformat(task.get('completed_at', task['created_at']))
                    if completed_time.date() == datetime.now().date():
                        completed_today += 1
                except:
                    continue
        
        return {
            "timestamp": datetime.now().isoformat(),
            "queues": queue_status,
            "summary": {
                "total_queued": sum(q["length"] for q in queue_status.values()),
                "total_processing": total_processing,
                "completed_today": completed_today
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get queue status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve queue status")

# Enhanced Campaign endpoints with Worker Integration
@app.post("/campaigns")
async def create_campaign(
    request: CampaignRequest,
    current_user: dict = Depends(get_admin_user)
):
    """Create and start a discovery campaign using worker system"""
    try:
        campaign_config = {
            "search_terms": request.search_terms,
            "max_sites": request.max_sites,
            "score_threshold": request.score_threshold,
            "email_enabled": request.email_enabled,
            "industry_filter": request.industry_filter
        }
        
        # Store campaign in database if available
        campaign_id = None
        if DATABASE_AVAILABLE:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()
            
            cur.execute("""
                INSERT INTO campaigns (name, config, status, created_at)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (request.name, json.dumps(campaign_config), 'running', datetime.now()))
            
            campaign_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()
        
        # Queue campaign task if worker system available
        if REDIS_AVAILABLE:
            task_id = await task_queue.add_task('campaign', {
                'type': 'discovery',
                'campaign_id': campaign_id,
                'config': campaign_config
            })
            
            return {
                "campaign_id": campaign_id,
                "task_id": task_id,
                "status": "queued",
                "message": f"Campaign '{request.name}' queued for processing",
                "check_status_url": f"/tasks/{task_id}/status"
            }
        else:
            # Run campaign immediately if no worker system
            from coderated_backend import CampaignManager
            campaign_manager = CampaignManager()
            result = await campaign_manager.run_discovery_campaign(campaign_config)
            
            if DATABASE_AVAILABLE and campaign_id:
                # Update campaign with results
                conn = psycopg2.connect(**DB_CONFIG)
                cur = conn.cursor()
                cur.execute("""
                    UPDATE campaigns 
                    SET status = 'completed', results = %s, completed_at = %s
                    WHERE id = %s
                """, (json.dumps(result), datetime.now(), campaign_id))
                conn.commit()
                cur.close()
                conn.close()
            
            return {
                "campaign_id": campaign_id,
                "status": "completed",
                "message": f"Campaign '{request.name}' completed",
                "results": result
            }
        
    except Exception as e:
        logger.error(f"Failed to create campaign: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create campaign")

# Enhanced Outreach endpoints with Worker Integration
@app.post("/outreach/batch")
async def send_batch_outreach(
    request: OutreachBatch,
    current_user: dict = Depends(get_admin_user)
):
    """Send batch outreach emails using worker system"""
    try:
        if not REDIS_AVAILABLE:
            raise HTTPException(status_code=503, detail="Worker system required for batch operations")
        
        # Queue batch outreach task
        task_id = await task_queue.add_task('campaign', {
            'type': 'outreach_batch',
            'leads': request.leads,
            'template_type': request.template_type
        })
        
        return {
            "task_id": task_id,
            "status": "queued",
            "message": f"Batch outreach queued for {len(request.leads)} leads",
            "check_status_url": f"/tasks/{task_id}/status"
        }
        
    except Exception as e:
        logger.error(f"Failed to queue batch outreach: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to queue batch outreach")

@app.post("/outreach/send")
async def send_outreach_email(
    request: OutreachEmail,
    current_user: dict = Depends(get_admin_user)
):
    """Send individual outreach email using worker system"""
    try:
        # Get website analysis for personalization
        if DATABASE_AVAILABLE:
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            cur.execute("""
                SELECT * FROM website_analyses 
                WHERE contact_email = %s 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (request.to_email,))
            
            analysis = cur.fetchone()
            
            if not analysis:
                raise HTTPException(status_code=404, detail="No analysis found for this email")
            
            # Check if already contacted recently
            cur.execute("""
                SELECT COUNT(*) FROM outreach_emails 
                WHERE to_email = %s AND sent_at > %s
            """, (request.to_email, datetime.now() - timedelta(days=30)))
            
            if cur.fetchone()[0] > 0:
                raise HTTPException(status_code=400, detail="Contact already reached out to recently")
            
            cur.close()
            conn.close()
            
            analysis_id = analysis['url']
        else:
            analysis_id = request.to_email  # Fallback for development
        
        # Queue outreach task if worker system available
        if REDIS_AVAILABLE:
            task_id = await task_queue.add_task('outreach', {
                'analysis_id': analysis_id,
                'template_type': request.template_type,
                'custom_message': request.custom_message
            })
            
            return {
                "task_id": task_id,
                "status": "queued",
                "message": f"Outreach email queued for {request.to_email}",
                "check_status_url": f"/tasks/{task_id}/status"
            }
        else:
            # Send immediately if no worker system
            return {
                "status": "sent",
                "message": f"Outreach email sent to {request.to_email} (immediate mode)"
            }
        
    except Exception as e:
        logger.error(f"Failed to send outreach: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send outreach email")

# Monitoring and Analytics endpoints
@app.get("/monitoring/health")
async def get_monitoring_health():
    """Get system health from monitoring system"""
    try:
        if not REDIS_AVAILABLE:
            return {"status": "monitoring_unavailable", "message": "Redis not available"}
        
        # Get latest metrics
        latest_metrics = await metrics_storage.get_latest_metrics()
        
        if not latest_metrics:
            return {"status": "no_metrics", "message": "No monitoring data available"}
        
        # Calculate simple health score
        health_score = 100
        issues = []
        
        if 'system' in latest_metrics:
            sys_data = latest_metrics['system']
            if sys_data.get('cpu_percent', 0) > 80:
                health_score -= 20
                issues.append(f"High CPU: {sys_data['cpu_percent']:.1f}%")
            if sys_data.get('memory_percent', 0) > 85:
                health_score -= 20
                issues.append(f"High Memory: {sys_data['memory_percent']:.1f}%")
        
        if 'queue' in latest_metrics:
            queue_data = latest_metrics['queue']
            total_queue = sum(queue_data.get('queue_lengths', {}).values())
            if total_queue > 100:
                health_score -= 15
                issues.append(f"High queue length: {total_queue}")
        
        status = "healthy" if health_score > 70 else "warning" if health_score > 50 else "critical"
        
        return {
            "status": status,
            "health_score": max(0, health_score),
            "issues": issues,
            "metrics": latest_metrics,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get monitoring health: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve monitoring health")

# Keep existing endpoints (analyses, campaigns list, etc.)
@app.get("/analyses", response_model=List[WebsiteAnalysisResponse])
async def get_analyses(
    limit: int = 50,
    offset: int = 0,
    industry: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get list of website analyses with filtering"""
    if not DATABASE_AVAILABLE:
        # Return mock data for development
        return []
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Build query with filters
        where_conditions = []
        params = []
        
        if industry:
            where_conditions.append("industry = %s")
            params.append(industry)
        
        if min_score is not None:
            where_conditions.append("score >= %s")
            params.append(min_score)
        
        if max_score is not None:
            where_conditions.append("score <= %s")
            params.append(max_score)
        
        # Restrict access based on user tier
        if current_user['tier'] == 'observer':
            where_conditions.append("created_at >= %s")
            params.append(datetime.now() - timedelta(days=7))
        
        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
        
        query = f"""
            SELECT id, url, domain, title, score, ux_design, seo_fundamentals,
                   speed_optimization, visual_identity, strategic_copy, industry,
                   contact_email, company_name, analysis_summary, created_at
            FROM website_analyses 
            WHERE {where_clause}
            ORDER BY created_at DESC 
            LIMIT %s OFFSET %s
        """
        
        params.extend([limit, offset])
        cur.execute(query, params)
        analyses = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return [dict(analysis) for analysis in analyses]
        
    except Exception as e:
        logger.error(f"Failed to get analyses: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analyses")

@app.get("/analysis/{analysis_id}")
async def get_analysis_detail(
    analysis_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed analysis by ID"""
    if not DATABASE_AVAILABLE:
        return {"error": "Database not available"}
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT * FROM website_analyses WHERE id = %s
        """, (analysis_id,))
        
        analysis = cur.fetchone()
        cur.close()
        conn.close()
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Check access permissions
        if current_user['tier'] == 'observer' and analysis['created_at'] < datetime.now() - timedelta(days=7):
            raise HTTPException(status_code=403, detail="Access denied. Upgrade for full history access.")
        
        return dict(analysis)
        
    except Exception as e:
        logger.error(f"Failed to get analysis detail: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analysis")

@app.get("/campaigns")
async def get_campaigns(
    limit: int = 20,
    offset: int = 0,
    current_user: dict = Depends(get_admin_user)
):
    """Get list of campaigns"""
    if not DATABASE_AVAILABLE:
        return []
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT id, name, status, created_at, completed_at, results
            FROM campaigns 
            ORDER BY created_at DESC 
            LIMIT %s OFFSET %s
        """, (limit, offset))
        
        campaigns = cur.fetchall()
        cur.close()
        conn.close()
        
        return [dict(campaign) for campaign in campaigns]
        
    except Exception as e:
        logger.error(f"Failed to get campaigns: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve campaigns")

@app.get("/campaigns/{campaign_id}")
async def get_campaign_detail(
    campaign_id: int,
    current_user: dict = Depends(get_admin_user)
):
    """Get detailed campaign information"""
    if not DATABASE_AVAILABLE:
        return {"error": "Database not available"}
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT * FROM campaigns WHERE id = %s", (campaign_id,))
        campaign = cur.fetchone()
        
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        
        cur.close()
        conn.close()
        
        return dict(campaign)
        
    except Exception as e:
        logger.error(f"Failed to get campaign detail: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve campaign")

@app.post("/outreach/leads")
async def get_outreach_leads(
    min_score: int = 0,
    max_score: int = 75,
    industry: Optional[str] = None,
    has_email: bool = True,
    limit: int = 50,
    current_user: dict = Depends(get_admin_user)
):
    """Get qualified leads for outreach"""
    if not DATABASE_AVAILABLE:
        return []
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        where_conditions = ["score BETWEEN %s AND %s"]
        params = [min_score, max_score]
        
        if has_email:
            where_conditions.append("contact_email IS NOT NULL")
        
        if industry:
            where_conditions.append("industry = %s")
            params.append(industry)
        
        # Exclude already contacted
        where_conditions.append("contacted_at IS NULL")
        
        where_clause = " AND ".join(where_conditions)
        
        query = f"""
            SELECT id, url, domain, title, score, industry, contact_email, 
                   company_name, analysis_summary, created_at
            FROM website_analyses 
            WHERE {where_clause}
            ORDER BY score ASC, created_at DESC 
            LIMIT %s
        """
        
        params.append(limit)
        cur.execute(query, params)
        leads = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return [dict(lead) for lead in leads]
        
    except Exception as e:
        logger.error(f"Failed to get leads: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve leads")

# Analytics and reporting endpoints
@app.get("/analytics/dashboard")
async def get_dashboard_analytics(
    days: int = 30,
    current_user: dict = Depends(get_current_user)
):
    """Get dashboard analytics"""
    if not DATABASE_AVAILABLE:
        return {
            "summary": {"total_analyses": 0, "avg_score": 0, "with_contact": 0},
            "score_distribution": {},
            "top_industries": [],
            "outreach_stats": {},
            "period_days": days
        }
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Date range
        start_date = datetime.now() - timedelta(days=days)
        
        # Total analyses
        cur.execute("""
            SELECT COUNT(*) as total_analyses,
                   AVG(score) as avg_score,
                   COUNT(CASE WHEN contact_email IS NOT NULL THEN 1 END) as with_contact
            FROM website_analyses 
            WHERE created_at >= %s
        """, (start_date,))
        
        summary = cur.fetchone()
        
        # Score distribution
        cur.execute("""
            SELECT 
                COUNT(CASE WHEN score >= 90 THEN 1 END) as excellent,
                COUNT(CASE WHEN score >= 80 AND score < 90 THEN 1 END) as good,
                COUNT(CASE WHEN score >= 70 AND score < 80 THEN 1 END) as fair,
                COUNT(CASE WHEN score >= 60 AND score < 70 THEN 1 END) as poor,
                COUNT(CASE WHEN score < 60 THEN 1 END) as critical
            FROM website_analyses 
            WHERE created_at >= %s
        """, (start_date,))
        
        score_distribution = cur.fetchone()
        
        # Industry breakdown
        cur.execute("""
            SELECT industry, COUNT(*) as count 
            FROM website_analyses 
            WHERE created_at >= %s AND industry IS NOT NULL
            GROUP BY industry 
            ORDER BY count DESC 
            LIMIT 10
        """, (start_date,))
        
        industries = cur.fetchall()
        
        # Outreach stats
        cur.execute("""
            SELECT COUNT(*) as emails_sent,
                   COUNT(CASE WHEN opened_at IS NOT NULL THEN 1 END) as emails_opened,
                   COUNT(CASE WHEN replied_at IS NOT NULL THEN 1 END) as emails_replied
            FROM outreach_emails 
            WHERE sent_at >= %s
        """, (start_date,))
        
        outreach_stats = cur.fetchone()
        
        cur.close()
        conn.close()
        
        return {
            "summary": dict(summary) if summary else {},
            "score_distribution": dict(score_distribution) if score_distribution else {},
            "top_industries": [dict(industry) for industry in industries],
            "outreach_stats": dict(outreach_stats) if outreach_stats else {},
            "period_days": days
        }
        
    except Exception as e:
        logger.error(f"Failed to get analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analytics")

@app.get("/analytics/trends")
async def get_trend_analytics(
    metric: str = "score",  # score, analyses_count, outreach_sent
    days: int = 30,
    current_user: dict = Depends(get_current_user)
):
    """Get trend analytics over time"""
    if not DATABASE_AVAILABLE:
        return {"metric": metric, "data": [], "period_days": days}
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        start_date = datetime.now() - timedelta(days=days)
        
        if metric == "score":
            query = """
                SELECT DATE(created_at) as date, AVG(score) as value
                FROM website_analyses 
                WHERE created_at >= %s
                GROUP BY DATE(created_at)
                ORDER BY date
            """
        elif metric == "analyses_count":
            query = """
                SELECT DATE(created_at) as date, COUNT(*) as value
                FROM website_analyses 
                WHERE created_at >= %s
                GROUP BY DATE(created_at)
                ORDER BY date
            """
        elif metric == "outreach_sent":
            query = """
                SELECT DATE(sent_at) as date, COUNT(*) as value
                FROM outreach_emails 
                WHERE sent_at >= %s
                GROUP BY DATE(sent_at)
                ORDER BY date
            """
        else:
            raise HTTPException(status_code=400, detail="Invalid metric")
        
        cur.execute(query, (start_date,))
        trends = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return {
            "metric": metric,
            "data": [{"date": trend["date"].isoformat(), "value": float(trend["value"])} for trend in trends],
            "period_days": days
        }
        
    except Exception as e:
        logger.error(f"Failed to get trends: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve trends")

# Utility functions
async def check_daily_analysis_limit(user_id: int) -> int:
    """Check user's daily analysis count"""
    if not DATABASE_AVAILABLE:
        return 0
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        today = datetime.now().date()
        cur.execute("""
            SELECT COUNT(*) FROM user_analyses 
            WHERE user_id = %s AND DATE(created_at) = %s
        """, (user_id, today))
        
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        
        return count
        
    except Exception:
        return 0

def format_analysis_response(analysis) -> dict:
    """Format analysis object for API response"""
    return {
        "url": analysis.url,
        "domain": analysis.domain,
        "title": analysis.title,
        "description": analysis.description,
        "score": analysis.score,
        "scores": {
            "ux_design": analysis.ux_design,
            "seo_fundamentals": analysis.seo_fundamentals,
            "speed_optimization": analysis.speed_optimization,
            "visual_identity": analysis.visual_identity,
            "strategic_copy": analysis.strategic_copy
        },
        "industry": analysis.industry,
        "contact_info": {
            "email": analysis.contact_email,
            "phone": analysis.phone,
            "company_name": analysis.company_name
        },
        "analysis_summary": analysis.analysis_summary,
        "timestamp": analysis.timestamp.isoformat()
    }

# WebSocket endpoints for real-time updates
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time updates including worker status"""
    await websocket.accept()
    
    try:
        while True:
            # Send periodic updates
            await asyncio.sleep(30)
            
            # Get user stats
            user_stats = await get_user_stats(user_id)
            
            # Add worker/queue status if available
            if REDIS_AVAILABLE:
                try:
                    queue_status = {}
                    queue_names = ['analysis_urgent', 'analysis_normal', 'analysis_batch', 'outreach']
                    for queue_name in queue_names:
                        queue_key = f"queue:{queue_name}"
                        length = redis_client.zcard(queue_key)
                        queue_status[queue_name] = length
                    
                    user_stats['queue_status'] = queue_status
                    user_stats['total_queued'] = sum(queue_status.values())
                    
                    # Worker health
                    worker_health = redis_client.get('worker:health')
                    if worker_health:
                        worker_data = json.loads(worker_health)
                        user_stats['worker_status'] = worker_data.get('worker_status', 'unknown')
                    else:
                        user_stats['worker_status'] = 'not_running'
                        
                except Exception as e:
                    user_stats['queue_error'] = str(e)
            
            await websocket.send_json(user_stats)
            
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {str(e)}")
    finally:
        await websocket.close()

async def get_user_stats(user_id: int) -> dict:
    """Get real-time stats for user"""
    if not DATABASE_AVAILABLE:
        return {
            "type": "stats_update",
            "data": {"analyses_today": 0},
            "timestamp": datetime.now().isoformat()
        }
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get user's recent activity
        cur.execute("""
            SELECT COUNT(*) as analyses_today
            FROM user_analyses 
            WHERE user_id = %s AND DATE(created_at) = %s
        """, (user_id, datetime.now().date()))
        
        stats = cur.fetchone()
        cur.close()
        conn.close()
        
        return {
            "type": "stats_update",
            "data": dict(stats) if stats else {},
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception:
        return {"type": "error", "message": "Failed to get stats"}

# Development endpoints for worker interaction
@app.post("/dev/queue-task")
async def queue_development_task(
    queue_name: str,
    task_data: Dict,
    current_user: dict = Depends(get_admin_user)
):
    """Development endpoint to manually queue tasks"""
    if not REDIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        task_id = await task_queue.add_task(queue_name, task_data)
        
        return {
            "task_id": task_id,
            "queue_name": queue_name,
            "status": "queued",
            "message": f"Task queued in {queue_name}"
        }
        
    except Exception as e:
        logger.error(f"Failed to queue development task: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to queue task")

@app.get("/dev/redis-info")
async def get_redis_info(current_user: dict = Depends(get_admin_user)):
    """Development endpoint to check Redis status"""
    if not REDIS_AVAILABLE:
        return {"status": "unavailable", "error": "Redis not connected"}
    
    try:
        info = redis_client.info()
        keys_count = redis_client.dbsize()
        
        return {
            "status": "connected",
            "redis_version": info.get('redis_version'),
            "keys_count": keys_count,
            "memory_usage": info.get('used_memory_human'),
            "connected_clients": info.get('connected_clients'),
            "uptime": info.get('uptime_in_seconds')
        }
        
    except Exception as e:
        return {"status": "error", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    
    # Create database tables on startup if database is available
    if DATABASE_AVAILABLE:
        try:
            from coderated_backend import create_database_tables
            create_database_tables()
        except Exception as e:
            logger.error(f"Failed to create database tables: {str(e)}")
    
    # Run the server
    uvicorn.run(
        "coderated_api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )