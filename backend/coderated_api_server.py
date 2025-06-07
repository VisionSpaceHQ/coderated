# CodeRated API Server - FastAPI Backend
# Production-ready API server for CodeRated platform

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict
import asyncio
import json
import os
from datetime import datetime, timedelta
import uuid
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
from passlib.context import CryptContext
import redis
from contextlib import asynccontextmanager

# Import our CodeRated backend
from coderated_backend import CodeRatedAnalyzer, EmailOutreachManager, CampaignManager, run_single_analysis

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="CodeRated API",
    description="AI-Powered Website Intelligence and Review Platform",
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

# Redis for caching
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

# Pydantic models
class AnalysisRequest(BaseModel):
    url: str
    priority: Optional[str] = "normal"  # normal, high, urgent

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
    return {"message": "CodeRated API v1.0", "status": "active"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        
        # Check Redis connection
        redis_client.ping()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "database": "connected",
                "redis": "connected",
                "ai_analyzer": "ready"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {str(e)}")

# Authentication endpoints
@app.post("/auth/register")
async def register_user(user: UserRegistration):
    """Register a new user"""
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

# Analysis endpoints
@app.post("/analyze", response_model=dict)
async def analyze_website(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Analyze a website and return CodeRated score"""
    
    # Check user tier permissions
    if current_user['tier'] == 'observer':
        # Check if user has exceeded free tier limits
        daily_limit = await check_daily_analysis_limit(current_user['id'])
        if daily_limit >= 5:  # Free tier limit
            raise HTTPException(status_code=403, detail="Daily analysis limit exceeded. Upgrade to continue.")
    
    try:
        # Check if analysis exists in cache
        cache_key = f"analysis:{request.url}"
        cached_result = redis_client.get(cache_key)
        
        if cached_result and request.priority == "normal":
            logger.info(f"Returning cached analysis for {request.url}")
            return json.loads(cached_result)
        
        # Add to analysis queue based on priority
        if request.priority == "urgent":
            # Run immediately
            analysis = await run_single_analysis(request.url)
            result = format_analysis_response(analysis)
        else:
            # Add to background queue
            background_tasks.add_task(analyze_website_background, request.url, current_user['id'])
            result = {
                "status": "queued",
                "message": f"Analysis queued for {request.url}",
                "estimated_completion": (datetime.now() + timedelta(minutes=5)).isoformat()
            }
        
        # Cache result
        redis_client.setex(cache_key, 3600, json.dumps(result))  # Cache for 1 hour
        
        return result
        
    except Exception as e:
        logger.error(f"Analysis failed for {request.url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

async def analyze_website_background(url: str, user_id: int):
    """Background task for website analysis"""
    try:
        analysis = await run_single_analysis(url)
        
        # Store analysis result
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            UPDATE website_analyses 
            SET status = 'completed', completed_at = %s 
            WHERE url = %s
        """, (datetime.now(), url))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Background analysis completed for {url}")
        
    except Exception as e:
        logger.error(f"Background analysis failed for {url}: {str(e)}")

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
            params.append(datetime.now() - timedelta(days=7))  # Only recent analyses
        
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

# Campaign management endpoints (Admin only)
@app.post("/campaigns")
async def create_campaign(
    request: CampaignRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_admin_user)
):
    """Create and start a discovery campaign"""
    try:
        # Store campaign in database
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        campaign_config = {
            "search_terms": request.search_terms,
            "max_sites": request.max_sites,
            "score_threshold": request.score_threshold,
            "email_enabled": request.email_enabled,
            "industry_filter": request.industry_filter
        }
        
        cur.execute("""
            INSERT INTO campaigns (name, config, status, created_at)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (request.name, json.dumps(campaign_config), 'running', datetime.now()))
        
        campaign_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        # Start campaign in background
        background_tasks.add_task(run_campaign_background, campaign_id, campaign_config)
        
        return {
            "campaign_id": campaign_id,
            "status": "started",
            "message": f"Campaign '{request.name}' started successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to create campaign: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create campaign")

async def run_campaign_background(campaign_id: int, config: dict):
    """Background task to run discovery campaign"""
    try:
        campaign_manager = CampaignManager()
        result = await campaign_manager.run_discovery_campaign(config)
        
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
        
        logger.info(f"Campaign {campaign_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Campaign {campaign_id} failed: {str(e)}")
        
        # Update campaign status to failed
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            UPDATE campaigns 
            SET status = 'failed', completed_at = %s
            WHERE id = %s
        """, (datetime.now(), campaign_id))
        conn.commit()
        cur.close()
        conn.close()

@app.get("/campaigns")
async def get_campaigns(
    limit: int = 20,
    offset: int = 0,
    current_user: dict = Depends(get_admin_user)
):
    """Get list of campaigns"""
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

# Outreach endpoints
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

@app.post("/outreach/send")
async def send_outreach_email(
    request: OutreachEmail,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_admin_user)
):
    """Send outreach email to specific lead"""
    try:
        # Get website analysis for personalization
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
        
        # Send email in background
        background_tasks.add_task(
            send_outreach_background, 
            dict(analysis), 
            request.template_type, 
            request.custom_message
        )
        
        return {
            "status": "queued",
            "message": f"Outreach email queued for {request.to_email}"
        }
        
    except Exception as e:
        logger.error(f"Failed to send outreach: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send outreach email")

async def send_outreach_background(analysis_data: dict, template_type: str, custom_message: str = None):
    """Background task to send outreach email"""
    try:
        # Convert dict back to WebsiteAnalysis object
        from coderated_backend import WebsiteAnalysis
        
        analysis = WebsiteAnalysis(
            url=analysis_data['url'],
            domain=analysis_data['domain'],
            title=analysis_data['title'],
            description=analysis_data['description'],
            score=analysis_data['score'],
            ux_design=analysis_data['ux_design'],
            seo_fundamentals=analysis_data['seo_fundamentals'],
            speed_optimization=analysis_data['speed_optimization'],
            visual_identity=analysis_data['visual_identity'],
            strategic_copy=analysis_data['strategic_copy'],
            industry=analysis_data['industry'],
            contact_email=analysis_data['contact_email'],
            phone=analysis_data['phone'],
            address=analysis_data['address'],
            company_name=analysis_data['company_name'],
            analysis_summary=analysis_data['analysis_summary'],
            technical_metrics=analysis_data['technical_metrics'],
            screenshots=[],
            timestamp=analysis_data['created_at']
        )
        
        email_manager = EmailOutreachManager()
        
        # Generate email content
        email_content = await email_manager.generate_outreach_email(analysis, template_type)
        
        # Add custom message if provided
        if custom_message:
            email_content['body'] = f"{custom_message}\n\n{email_content['body']}"
        
        # Send email
        success = await email_manager.send_outreach_email(
            analysis.contact_email,
            email_content['subject'],
            email_content['body']
        )
        
        if success:
            # Mark as contacted
            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()
            cur.execute("""
                UPDATE website_analyses 
                SET contacted_at = %s 
                WHERE contact_email = %s
            """, (datetime.now(), analysis.contact_email))
            conn.commit()
            cur.close()
            conn.close()
            
            logger.info(f"Outreach email sent successfully to {analysis.contact_email}")
        
    except Exception as e:
        logger.error(f"Failed to send outreach email: {str(e)}")

# Analytics and reporting endpoints
@app.get("/analytics/dashboard")
async def get_dashboard_analytics(
    days: int = 30,
    current_user: dict = Depends(get_current_user)
):
    """Get dashboard analytics"""
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
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    
    try:
        while True:
            # Send periodic updates
            await asyncio.sleep(30)
            
            # Get latest stats for user
            stats = await get_user_stats(user_id)
            await websocket.send_json(stats)
            
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {str(e)}")
    finally:
        await websocket.close()

async def get_user_stats(user_id: int) -> dict:
    """Get real-time stats for user"""
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

if __name__ == "__main__":
    import uvicorn
    
    # Create database tables on startup
    from coderated_backend import create_database_tables
    create_database_tables()
    
    # Run the server
    uvicorn.run(
        "coderated_api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
