# CodeRated Worker - Background Task Processor
# Handles asynchronous website analysis, email outreach, and campaign processing

import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
import redis
from dataclasses import asdict

# Import CodeRated modules
from coderated_backend import (
    CodeRatedAnalyzer, 
    EmailOutreachManager, 
    CampaignManager, 
    WebsiteAnalysis,
    run_single_analysis
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TaskQueue:
    """Redis-based task queue for background processing"""
    
    def __init__(self):
        self.redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            decode_responses=True
        )
        self.task_queues = {
            'analysis_urgent': 'queue:analysis:urgent',
            'analysis_normal': 'queue:analysis:normal', 
            'analysis_batch': 'queue:analysis:batch',
            'outreach': 'queue:outreach',
            'campaign': 'queue:campaign',
            'cleanup': 'queue:cleanup'
        }
    
    async def add_task(self, queue_name: str, task_data: Dict, priority: int = 0):
        """Add task to queue with priority"""
        try:
            task = {
                'id': f"task_{int(time.time())}_{queue_name}",
                'type': queue_name,
                'data': task_data,
                'created_at': datetime.now().isoformat(),
                'priority': priority,
                'retries': 0,
                'max_retries': 3
            }
            
            queue_key = self.task_queues.get(queue_name, f"queue:{queue_name}")
            
            # Use sorted set for priority queues
            score = priority * 1000000 + int(time.time())
            self.redis_client.zadd(queue_key, {json.dumps(task): score})
            
            logger.info(f"Task added to {queue_name}: {task['id']}")
            return task['id']
            
        except Exception as e:
            logger.error(f"Failed to add task to {queue_name}: {str(e)}")
            return None
    
    async def get_task(self, queue_name: str) -> Optional[Dict]:
        """Get next task from queue"""
        try:
            queue_key = self.task_queues.get(queue_name, f"queue:{queue_name}")
            
            # Get highest priority task
            result = self.redis_client.zpopmin(queue_key, count=1)
            
            if result:
                task_json, score = result[0]
                task = json.loads(task_json)
                
                # Mark task as processing
                processing_key = f"processing:{task['id']}"
                self.redis_client.setex(processing_key, 3600, json.dumps(task))
                
                return task
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get task from {queue_name}: {str(e)}")
            return None
    
    async def complete_task(self, task_id: str):
        """Mark task as completed"""
        try:
            processing_key = f"processing:{task_id}"
            completed_key = f"completed:{task_id}"
            
            # Move from processing to completed
            task_data = self.redis_client.get(processing_key)
            if task_data:
                self.redis_client.setex(completed_key, 86400, task_data)  # Keep for 24 hours
                self.redis_client.delete(processing_key)
                
            logger.info(f"Task completed: {task_id}")
            
        except Exception as e:
            logger.error(f"Failed to complete task {task_id}: {str(e)}")
    
    async def fail_task(self, task_id: str, error: str):
        """Mark task as failed and potentially retry"""
        try:
            processing_key = f"processing:{task_id}"
            task_data = self.redis_client.get(processing_key)
            
            if task_data:
                task = json.loads(task_data)
                task['retries'] += 1
                task['last_error'] = error
                task['failed_at'] = datetime.now().isoformat()
                
                if task['retries'] < task['max_retries']:
                    # Retry with exponential backoff
                    delay = 2 ** task['retries'] * 60  # 2min, 4min, 8min
                    retry_time = int(time.time()) + delay
                    
                    queue_key = self.task_queues.get(task['type'], f"queue:{task['type']}")
                    score = task['priority'] * 1000000 + retry_time
                    
                    self.redis_client.zadd(queue_key, {json.dumps(task): score})
                    logger.info(f"Task {task_id} scheduled for retry in {delay} seconds")
                else:
                    # Max retries reached, move to failed
                    failed_key = f"failed:{task_id}"
                    self.redis_client.setex(failed_key, 86400 * 7, json.dumps(task))  # Keep for 7 days
                    logger.error(f"Task {task_id} failed permanently after {task['retries']} retries")
                
                self.redis_client.delete(processing_key)
                
        except Exception as e:
            logger.error(f"Failed to handle task failure {task_id}: {str(e)}")

class CodeRatedWorker:
    """Main worker class for processing background tasks"""
    
    def __init__(self):
        self.queue = TaskQueue()
        self.analyzer = CodeRatedAnalyzer()
        self.email_manager = EmailOutreachManager()
        self.campaign_manager = CampaignManager()
        self.running = False
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'coderated'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD')
        }
        
        # Task handlers
        self.task_handlers = {
            'analysis_urgent': self.handle_website_analysis,
            'analysis_normal': self.handle_website_analysis,
            'analysis_batch': self.handle_website_analysis,
            'outreach': self.handle_outreach_email,
            'campaign': self.handle_campaign,
            'cleanup': self.handle_cleanup
        }
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    async def start(self):
        """Start the worker"""
        logger.info("🚀 CodeRated Worker starting...")
        self.running = True
        
        # Start multiple worker coroutines for different queue types
        workers = [
            asyncio.create_task(self.worker_loop('analysis_urgent', 1)),    # Urgent analysis
            asyncio.create_task(self.worker_loop('analysis_normal', 2)),    # Normal analysis 
            asyncio.create_task(self.worker_loop('analysis_batch', 5)),     # Batch analysis
            asyncio.create_task(self.worker_loop('outreach', 3)),           # Email outreach
            asyncio.create_task(self.worker_loop('campaign', 10)),          # Campaign processing
            asyncio.create_task(self.worker_loop('cleanup', 60)),           # Cleanup tasks
            asyncio.create_task(self.health_monitor())                      # Health monitoring
        ]
        
        try:
            await asyncio.gather(*workers)
        except Exception as e:
            logger.error(f"Worker error: {str(e)}")
        finally:
            logger.info("🛑 CodeRated Worker stopped")
    
    async def worker_loop(self, queue_name: str, sleep_interval: int = 5):
        """Main worker loop for processing tasks"""
        logger.info(f"Worker started for queue: {queue_name}")
        
        while self.running:
            try:
                # Get next task from queue
                task = await self.queue.get_task(queue_name)
                
                if task:
                    await self.process_task(task)
                else:
                    # No tasks, sleep before checking again
                    await asyncio.sleep(sleep_interval)
                    
            except Exception as e:
                logger.error(f"Error in worker loop {queue_name}: {str(e)}")
                await asyncio.sleep(sleep_interval)
        
        logger.info(f"Worker stopped for queue: {queue_name}")
    
    async def process_task(self, task: Dict):
        """Process a single task"""
        task_id = task['id']
        task_type = task['type']
        
        logger.info(f"Processing task {task_id} of type {task_type}")
        
        try:
            # Get handler for task type
            handler = self.task_handlers.get(task_type)
            
            if handler:
                await handler(task)
                await self.queue.complete_task(task_id)
                logger.info(f"✅ Task {task_id} completed successfully")
            else:
                raise Exception(f"No handler found for task type: {task_type}")
                
        except Exception as e:
            error_msg = f"Task {task_id} failed: {str(e)}"
            logger.error(error_msg)
            await self.queue.fail_task(task_id, error_msg)
    
    async def handle_website_analysis(self, task: Dict):
        """Handle website analysis tasks"""
        data = task['data']
        url = data['url']
        user_id = data.get('user_id')
        priority = data.get('priority', 'normal')
        
        try:
            # Run analysis
            analysis = await run_single_analysis(url)
            
            # Store analysis in database with user association
            await self.store_user_analysis(analysis, user_id)
            
            # If urgent priority, also cache result
            if priority == 'urgent':
                cache_key = f"analysis:{url}"
                analysis_dict = asdict(analysis)
                analysis_dict['timestamp'] = analysis_dict['timestamp'].isoformat()
                
                self.queue.redis_client.setex(
                    cache_key, 
                    3600,  # 1 hour
                    json.dumps(analysis_dict)
                )
            
            # Trigger outreach if qualified
            if (analysis.contact_email and 
                analysis.score < 75 and 
                data.get('auto_outreach', False)):
                
                await self.queue.add_task('outreach', {
                    'analysis_id': analysis.url,  # Use URL as ID for now
                    'template_type': 'opportunity'
                })
            
            logger.info(f"Analysis completed for {url} - Score: {analysis.score}")
            
        except Exception as e:
            logger.error(f"Website analysis failed for {url}: {str(e)}")
            raise
    
    async def handle_outreach_email(self, task: Dict):
        """Handle email outreach tasks"""
        data = task['data']
        
        try:
            # Get analysis data
            analysis_data = await self.get_analysis_data(data['analysis_id'])
            
            if not analysis_data or not analysis_data.get('contact_email'):
                raise Exception("No contact email found for outreach")
            
            # Check if already contacted recently
            if await self.already_contacted(analysis_data['contact_email']):
                logger.info(f"Skipping outreach - already contacted {analysis_data['contact_email']}")
                return
            
            # Generate email content
            template_type = data.get('template_type', 'opportunity')
            custom_message = data.get('custom_message')
            
            # Convert dict back to WebsiteAnalysis object for email generation
            analysis = self.dict_to_analysis(analysis_data)
            
            email_content = await self.email_manager.generate_outreach_email(
                analysis, template_type
            )
            
            if custom_message:
                email_content['body'] = f"{custom_message}\n\n{email_content['body']}"
            
            # Send email
            success = await self.email_manager.send_outreach_email(
                analysis.contact_email,
                email_content['subject'],
                email_content['body']
            )
            
            if success:
                # Mark as contacted
                await self.mark_as_contacted(analysis.contact_email)
                logger.info(f"Outreach email sent to {analysis.contact_email}")
            
        except Exception as e:
            logger.error(f"Outreach failed: {str(e)}")
            raise
    
    async def handle_campaign(self, task: Dict):
        """Handle campaign processing tasks"""
        data = task['data']
        campaign_type = data.get('type', 'discovery')
        
        try:
            if campaign_type == 'discovery':
                config = data.get('config', {})
                result = await self.campaign_manager.run_discovery_campaign(config)
                
                # Store campaign results
                await self.store_campaign_results(data.get('campaign_id'), result)
                
                logger.info(f"Discovery campaign completed: {result['campaign_summary']}")
                
            elif campaign_type == 'outreach_batch':
                # Process batch outreach
                leads = data.get('leads', [])
                
                for lead in leads:
                    await self.queue.add_task('outreach', {
                        'analysis_id': lead['analysis_id'],
                        'template_type': lead.get('template_type', 'opportunity')
                    })
                
                logger.info(f"Batch outreach queued for {len(leads)} leads")
                
        except Exception as e:
            logger.error(f"Campaign processing failed: {str(e)}")
            raise
    
    async def handle_cleanup(self, task: Dict):
        """Handle cleanup and maintenance tasks"""
        data = task['data']
        cleanup_type = data.get('type', 'old_tasks')
        
        try:
            if cleanup_type == 'old_tasks':
                # Clean up old completed/failed tasks
                await self.cleanup_old_tasks()
                
            elif cleanup_type == 'cache_refresh':
                # Refresh analysis cache for popular sites
                await self.refresh_popular_cache()
                
            elif cleanup_type == 'database_maintenance':
                # Database cleanup and optimization
                await self.database_maintenance()
                
            logger.info(f"Cleanup completed: {cleanup_type}")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
            raise
    
    async def health_monitor(self):
        """Monitor worker health and queue status"""
        while self.running:
            try:
                # Check queue lengths
                queue_stats = {}
                for queue_name, queue_key in self.queue.task_queues.items():
                    length = self.queue.redis_client.zcard(queue_key)
                    queue_stats[queue_name] = length
                
                # Log queue status
                total_pending = sum(queue_stats.values())
                if total_pending > 0:
                    logger.info(f"Queue status: {queue_stats} (Total: {total_pending})")
                
                # Check for stuck tasks
                await self.check_stuck_tasks()
                
                # Update health metrics
                await self.update_health_metrics(queue_stats)
                
                # Sleep for monitoring interval
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Health monitor error: {str(e)}")
                await asyncio.sleep(30)
    
    async def check_stuck_tasks(self):
        """Check for and recover stuck tasks"""
        try:
            # Find processing tasks older than 1 hour
            pattern = "processing:*"
            keys = self.queue.redis_client.keys(pattern)
            
            for key in keys:
                task_data = self.queue.redis_client.get(key)
                if task_data:
                    task = json.loads(task_data)
                    created_at = datetime.fromisoformat(task['created_at'])
                    
                    if datetime.now() - created_at > timedelta(hours=1):
                        # Task is stuck, move back to queue
                        task_id = task['id']
                        logger.warning(f"Recovering stuck task: {task_id}")
                        
                        await self.queue.fail_task(task_id, "Task timeout - recovered")
                        
        except Exception as e:
            logger.error(f"Error checking stuck tasks: {str(e)}")
    
    async def store_user_analysis(self, analysis: WebsiteAnalysis, user_id: Optional[int]):
        """Store analysis with user association"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            # Store main analysis
            insert_query = """
            INSERT INTO website_analyses 
            (url, domain, title, description, score, ux_design, seo_fundamentals, 
             speed_optimization, visual_identity, strategic_copy, industry, 
             contact_email, phone, address, company_name, analysis_summary, 
             technical_metrics, created_at) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """
            
            cur.execute(insert_query, (
                analysis.url, analysis.domain, analysis.title, analysis.description,
                analysis.score, analysis.ux_design, analysis.seo_fundamentals,
                analysis.speed_optimization, analysis.visual_identity, analysis.strategic_copy,
                analysis.industry, analysis.contact_email, analysis.phone, analysis.address,
                analysis.company_name, json.dumps(analysis.analysis_summary),
                json.dumps(analysis.technical_metrics), analysis.timestamp
            ))
            
            analysis_id = cur.fetchone()[0]
            
            # Store user association if provided
            if user_id:
                cur.execute("""
                    INSERT INTO user_analyses (user_id, analysis_id, created_at)
                    VALUES (%s, %s, %s)
                """, (user_id, analysis_id, datetime.now()))
            
            conn.commit()
            cur.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store analysis: {str(e)}")
            raise
    
    # Additional helper methods...
    async def get_analysis_data(self, analysis_id: str) -> Optional[Dict]:
        """Get analysis data by ID or URL"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            cur.execute("""
                SELECT * FROM website_analyses 
                WHERE url = %s OR id::text = %s
                ORDER BY created_at DESC 
                LIMIT 1
            """, (analysis_id, analysis_id))
            
            result = cur.fetchone()
            cur.close()
            conn.close()
            
            return dict(result) if result else None
            
        except Exception as e:
            logger.error(f"Failed to get analysis data: {str(e)}")
            return None
    
    def dict_to_analysis(self, data: Dict) -> WebsiteAnalysis:
        """Convert dictionary to WebsiteAnalysis object"""
        return WebsiteAnalysis(
            url=data['url'],
            domain=data['domain'],
            title=data['title'],
            description=data['description'],
            score=data['score'],
            ux_design=data['ux_design'],
            seo_fundamentals=data['seo_fundamentals'],
            speed_optimization=data['speed_optimization'],
            visual_identity=data['visual_identity'],
            strategic_copy=data['strategic_copy'],
            industry=data['industry'],
            contact_email=data['contact_email'],
            phone=data['phone'],
            address=data['address'],
            company_name=data['company_name'],
            analysis_summary=data['analysis_summary'],
            technical_metrics=data['technical_metrics'],
            screenshots=[],
            timestamp=data['created_at']
        )
    
    async def already_contacted(self, email: str) -> bool:
        """Check if email was contacted recently"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            cur.execute("""
                SELECT COUNT(*) FROM outreach_emails 
                WHERE to_email = %s AND sent_at > %s
            """, (email, datetime.now() - timedelta(days=30)))
            
            count = cur.fetchone()[0]
            cur.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking contact history: {str(e)}")
            return False
    
    async def mark_as_contacted(self, email: str):
        """Mark email as contacted"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            cur.execute("""
                UPDATE website_analyses 
                SET contacted_at = %s 
                WHERE contact_email = %s
            """, (datetime.now(), email))
            
            conn.commit()
            cur.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error marking as contacted: {str(e)}")
    
    async def cleanup_old_tasks(self):
        """Clean up old completed and failed tasks"""
        try:
            # Remove completed tasks older than 24 hours
            completed_keys = self.queue.redis_client.keys("completed:*")
            failed_keys = self.queue.redis_client.keys("failed:*")
            
            cleaned_count = 0
            for key in completed_keys + failed_keys:
                # Check if key is old enough to delete
                ttl = self.queue.redis_client.ttl(key)
                if ttl < 0:  # No expiration set or already expired
                    self.queue.redis_client.delete(key)
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} old task records")
                
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")
    
    async def update_health_metrics(self, queue_stats: Dict):
        """Update health metrics in Redis"""
        try:
            health_data = {
                'timestamp': datetime.now().isoformat(),
                'queue_stats': queue_stats,
                'worker_status': 'healthy',
                'total_pending': sum(queue_stats.values())
            }
            
            self.queue.redis_client.setex(
                'worker:health', 
                300,  # 5 minutes
                json.dumps(health_data)
            )
            
        except Exception as e:
            logger.error(f"Failed to update health metrics: {str(e)}")

# CLI interface
async def main():
    """Main entry point"""
    worker = CodeRatedWorker()
    
    try:
        await worker.start()
    except KeyboardInterrupt:
        logger.info("Worker interrupted by user")
    except Exception as e:
        logger.error(f"Worker failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Handle command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "add-task":
            # Example: python worker.py add-task analysis_normal '{"url": "https://example.com"}'
            if len(sys.argv) >= 4:
                queue_name = sys.argv[2]
                task_data = json.loads(sys.argv[3])
                
                async def add_task():
                    queue = TaskQueue()
                    task_id = await queue.add_task(queue_name, task_data)
                    print(f"Task added: {task_id}")
                
                asyncio.run(add_task())
            else:
                print("Usage: python worker.py add-task <queue_name> '<task_data_json>'")
        
        elif command == "status":
            # Show queue status
            async def show_status():
                queue = TaskQueue()
                for queue_name, queue_key in queue.task_queues.items():
                    length = queue.redis_client.zcard(queue_key)
                    print(f"{queue_name}: {length} tasks")
            
            asyncio.run(show_status())
        
        else:
            print("Unknown command. Available: add-task, status")
    else:
        # Start worker
        asyncio.run(main())