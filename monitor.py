# monitor.py - Basic monitoring for CodeRated
import time
import json
from datetime import datetime
from typing import Dict, Any, Optional

class MetricsStorage:
    """Simple in-memory metrics storage"""
    
    def __init__(self):
        self.metrics = []
        self.requests_count = 0
        self.errors_count = 0
        self.response_times = []
    
    def record_request(self, endpoint: str, method: str, status_code: int, response_time: float):
        """Record a request metric"""
        self.requests_count += 1
        if status_code >= 400:
            self.errors_count += 1
        
        self.response_times.append(response_time)
        
        metric = {
            'timestamp': datetime.now().isoformat(),
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time': response_time
        }
        self.metrics.append(metric)
        
        # Keep only last 1000 metrics
        if len(self.metrics) > 1000:
            self.metrics = self.metrics[-1000:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current stats"""
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        return {
            'total_requests': self.requests_count,
            'total_errors': self.errors_count,
            'error_rate': self.errors_count / self.requests_count if self.requests_count > 0 else 0,
            'avg_response_time': avg_response_time,
            'recent_metrics': self.metrics[-10:]  # Last 10 requests
        }

class CodeRatedMonitor:
    """Main monitoring class for CodeRated API"""
    
    def __init__(self):
        self.storage = MetricsStorage()
        self.start_time = time.time()
    
    def request_middleware(self, app):
        """Flask middleware to monitor requests"""
        @app.before_request
        def before_request():
            app.request_start_time = time.time()
        
        @app.after_request
        def after_request(response):
            if hasattr(app, 'request_start_time'):
                response_time = time.time() - app.request_start_time
                from flask import request
                
                self.storage.record_request(
                    endpoint=request.endpoint or request.path,
                    method=request.method,
                    status_code=response.status_code,
                    response_time=response_time
                )
            
            return response
        
        return app
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get API health status"""
        uptime = time.time() - self.start_time
        stats = self.storage.get_stats()
        
        return {
            'status': 'healthy',
            'uptime_seconds': uptime,
            'uptime_formatted': f"{uptime/3600:.1f} hours",
            'metrics': stats
        }
    
    def log_analysis_request(self, url: str, success: bool, analysis_time: float):
        """Log a website analysis request"""
        print(f"[ANALYSIS] URL: {url}, Success: {success}, Time: {analysis_time:.2f}s")
        
        # You could extend this to store in database, send to external monitoring, etc.

# Create a global monitor instance
monitor = CodeRatedMonitor()