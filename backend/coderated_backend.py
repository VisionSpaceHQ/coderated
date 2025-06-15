# CodeRated Backend - AI Website Analysis System
# Core modules for automated website discovery, analysis, and outreach

import asyncio
import aiohttp
import json
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import openai
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import whois
import dns.resolver
import ssl
import subprocess
import logging
from typing import Dict, List, Optional, Tuple
import os
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import time
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class WebsiteAnalysis:
    """Data structure for website analysis results"""
    url: str
    domain: str
    title: str
    description: str
    score: int
    ux_design: int
    seo_fundamentals: int
    speed_optimization: int
    visual_identity: int
    strategic_copy: int
    industry: str
    contact_email: Optional[str]
    phone: Optional[str]
    address: Optional[str]
    company_name: str
    analysis_summary: Dict[str, str]
    technical_metrics: Dict[str, any]
    screenshots: List[str]
    timestamp: datetime

class CodeRatedAnalyzer:
    """Main analyzer class for CodeRated website intelligence"""
    
    def __init__(self):
        self.openai_client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'coderated'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD')
        }
        self.setup_chrome_driver()
        
    def setup_chrome_driver(self):
        """Configure Chrome driver for web scraping"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        self.chrome_options = chrome_options

    async def discover_websites(self, search_terms: List[str], max_results: int = 100) -> List[str]:
        """Discover websites using various methods"""
        discovered_urls = set()
        
        # Method 1: Google search-based discovery
        for term in search_terms:
            urls = await self._google_search_discovery(term, max_results // len(search_terms))
            discovered_urls.update(urls)
        
        # Method 2: Domain enumeration
        domain_urls = await self._domain_enumeration_discovery()
        discovered_urls.update(domain_urls)
        
        # Method 3: Industry-specific discovery
        industry_urls = await self._industry_specific_discovery()
        discovered_urls.update(industry_urls)
        
        return list(discovered_urls)[:max_results]

    async def _google_search_discovery(self, term: str, limit: int) -> List[str]:
        """Discover websites through search engines"""
        # Note: In production, use proper Google Search API or SerpAPI
        # This is a simplified example
        search_queries = [
            f'"{term}" site:*.com',
            f'{term} business website',
            f'{term} company site',
            f'"{term}" contact us'
        ]
        
        discovered = []
        async with aiohttp.ClientSession() as session:
            for query in search_queries:
                # Implement actual search API calls here
                # For now, return mock data
                mock_urls = [
                    f"https://example-{term.replace(' ', '')}-{i}.com" 
                    for i in range(limit // len(search_queries))
                ]
                discovered.extend(mock_urls)
        
        return discovered

    async def _domain_enumeration_discovery(self) -> List[str]:
        """Discover websites through domain enumeration"""
        # Common business domain patterns
        patterns = [
            "local{}.com", "best{}.com", "{}-shop.com", 
            "{}services.com", "{}company.com"
        ]
        
        business_types = ["bakery", "restaurant", "dental", "law", "realty"]
        discovered = []
        
        for business in business_types:
            for pattern in patterns:
                domain = pattern.format(business)
                if await self._check_domain_exists(domain):
                    discovered.append(f"https://{domain}")
        
        return discovered

    async def _industry_specific_discovery(self) -> List[str]:
        """Target specific industries for discovery"""
        # Industry-specific sources and directories
        industry_sources = {
            'local_business': ['yelp.com', 'yellowpages.com'],
            'ecommerce': ['shopify.com', 'woocommerce.com'],
            'professional': ['linkedin.com', 'justia.com']
        }
        
        discovered = []
        # Implement industry-specific scraping logic
        return discovered

    async def _check_domain_exists(self, domain: str) -> bool:
        """Check if a domain exists and is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}", timeout=5) as response:
                    return response.status == 200
        except:
            return False

    async def analyze_website(self, url: str) -> WebsiteAnalysis:
        """Comprehensive website analysis"""
        logger.info(f"Starting analysis for {url}")
        
        # Initialize analysis object
        domain = urlparse(url).netloc
        analysis = WebsiteAnalysis(
            url=url,
            domain=domain,
            title="",
            description="",
            score=0,
            ux_design=0,
            seo_fundamentals=0,
            speed_optimization=0,
            visual_identity=0,
            strategic_copy=0,
            industry="",
            contact_email=None,
            phone=None,
            address=None,
            company_name="",
            analysis_summary={},
            technical_metrics={},
            screenshots=[],
            timestamp=datetime.now()
        )
        
        try:
            # Step 1: Technical analysis
            technical_data = await self._technical_analysis(url)
            analysis.technical_metrics = technical_data
            
            # Step 2: Content analysis
            content_data = await self._content_analysis(url)
            analysis.title = content_data.get('title', '')
            analysis.description = content_data.get('description', '')
            
            # Step 3: Contact information extraction
            contact_info = await self._extract_contact_info(url)
            analysis.contact_email = contact_info.get('email')
            analysis.phone = contact_info.get('phone')
            analysis.address = contact_info.get('address')
            analysis.company_name = contact_info.get('company_name', '')
            
            # Step 4: Industry classification
            analysis.industry = await self._classify_industry(content_data)
            
            # Step 5: Generate scores using AI
            scores = await self._generate_ai_scores(url, technical_data, content_data)
            analysis.ux_design = scores['ux_design']
            analysis.seo_fundamentals = scores['seo_fundamentals']
            analysis.speed_optimization = scores['speed_optimization']
            analysis.visual_identity = scores['visual_identity']
            analysis.strategic_copy = scores['strategic_copy']
            analysis.score = sum(scores.values()) // len(scores)
            
            # Step 6: Generate AI summary
            analysis.analysis_summary = await self._generate_ai_summary(analysis)
            
            # Step 7: Take screenshots
            analysis.screenshots = await self._capture_screenshots(url)
            
            # Step 8: Store in database
            await self._store_analysis(analysis)
            
            logger.info(f"Analysis completed for {url} - Score: {analysis.score}")
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis failed for {url}: {str(e)}")
            raise

    async def _technical_analysis(self, url: str) -> Dict:
        """Perform technical website analysis"""
        metrics = {}
        
        try:
            # Lighthouse analysis (requires lighthouse CLI)
            lighthouse_result = await self._run_lighthouse(url)
            metrics['lighthouse'] = lighthouse_result
            
            # SSL/Security check
            ssl_info = await self._check_ssl(url)
            metrics['ssl'] = ssl_info
            
            # Page speed analysis
            speed_metrics = await self._analyze_page_speed(url)
            metrics['speed'] = speed_metrics
            
            # Mobile responsiveness
            mobile_metrics = await self._check_mobile_responsiveness(url)
            metrics['mobile'] = mobile_metrics
            
            # SEO technical factors
            seo_metrics = await self._analyze_technical_seo(url)
            metrics['seo_technical'] = seo_metrics
            
        except Exception as e:
            logger.error(f"Technical analysis failed for {url}: {str(e)}")
            metrics['error'] = str(e)
        
        return metrics

    async def _run_lighthouse(self, url: str) -> Dict:
        """Run Google Lighthouse analysis"""
        try:
            # Run lighthouse command
            cmd = [
                'lighthouse', url,
                '--output=json',
                '--quiet',
                '--chrome-flags=--headless'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                lighthouse_data = json.loads(result.stdout)
                return {
                    'performance': lighthouse_data['lhr']['categories']['performance']['score'] * 100,
                    'accessibility': lighthouse_data['lhr']['categories']['accessibility']['score'] * 100,
                    'best_practices': lighthouse_data['lhr']['categories']['best-practices']['score'] * 100,
                    'seo': lighthouse_data['lhr']['categories']['seo']['score'] * 100,
                    'first_contentful_paint': lighthouse_data['lhr']['audits']['first-contentful-paint']['numericValue'],
                    'largest_contentful_paint': lighthouse_data['lhr']['audits']['largest-contentful-paint']['numericValue']
                }
        except Exception as e:
            logger.error(f"Lighthouse analysis failed: {str(e)}")
        
        return {'error': 'Lighthouse analysis failed'}

    async def _content_analysis(self, url: str) -> Dict:
        """Analyze website content"""
        driver = webdriver.Chrome(options=self.chrome_options)
        content_data = {}
        
        try:
            driver.get(url)
            time.sleep(3)  # Wait for page load
            
            # Extract basic page info
            content_data['title'] = driver.title
            content_data['url'] = driver.current_url
            
            # Get page source for BeautifulSoup analysis
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            
            # Meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            content_data['description'] = meta_desc.get('content', '') if meta_desc else ''
            
            # Headings structure
            headings = {}
            for i in range(1, 7):
                headings[f'h{i}'] = [h.get_text().strip() for h in soup.find_all(f'h{i}')]
            content_data['headings'] = headings
            
            # Text content
            content_data['body_text'] = soup.get_text()
            
            # Images
            images = soup.find_all('img')
            content_data['images'] = [{
                'src': img.get('src', ''),
                'alt': img.get('alt', ''),
                'title': img.get('title', '')
            } for img in images]
            
            # Links
            links = soup.find_all('a', href=True)
            content_data['links'] = [link['href'] for link in links]
            
            # Forms
            forms = soup.find_all('form')
            content_data['forms'] = len(forms)
            
            # Social media links
            social_patterns = {
                'facebook': r'facebook\.com',
                'twitter': r'twitter\.com|x\.com',
                'instagram': r'instagram\.com',
                'linkedin': r'linkedin\.com',
                'youtube': r'youtube\.com'
            }
            
            social_links = {}
            for platform, pattern in social_patterns.items():
                social_links[platform] = bool(re.search(pattern, str(soup)))
            content_data['social_media'] = social_links
            
        except Exception as e:
            logger.error(f"Content analysis failed for {url}: {str(e)}")
            content_data['error'] = str(e)
        finally:
            driver.quit()
        
        return content_data

    async def _extract_contact_info(self, url: str) -> Dict:
        """Extract contact information from website"""
        driver = webdriver.Chrome(options=self.chrome_options)
        contact_info = {}
        
        try:
            # Check main page and common contact pages
            pages_to_check = [url, f"{url}/contact", f"{url}/about", f"{url}/contact-us"]
            
            for page_url in pages_to_check:
                try:
                    driver.get(page_url)
                    time.sleep(2)
                    
                    soup = BeautifulSoup(driver.page_source, 'html.parser')
                    page_text = soup.get_text()
                    
                    # Extract email
                    if not contact_info.get('email'):
                        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                        emails = re.findall(email_pattern, page_text)
                        if emails:
                            # Filter out common non-contact emails
                            filtered_emails = [e for e in emails if not any(
                                excluded in e.lower() for excluded in 
                                ['noreply', 'support@', 'admin@', 'no-reply']
                            )]
                            if filtered_emails:
                                contact_info['email'] = filtered_emails[0]
                    
                    # Extract phone
                    if not contact_info.get('phone'):
                        phone_pattern = r'(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})'
                        phones = re.findall(phone_pattern, page_text)
                        if phones:
                            contact_info['phone'] = phones[0]
                    
                    # Extract address
                    if not contact_info.get('address'):
                        # Look for address patterns
                        address_indicators = ['address', 'location', 'visit us', 'find us']
                        for indicator in address_indicators:
                            if indicator in page_text.lower():
                                # Extract surrounding text (simplified)
                                lines = page_text.split('\n')
                                for i, line in enumerate(lines):
                                    if indicator in line.lower() and len(line) > 20:
                                        contact_info['address'] = line.strip()
                                        break
                                if contact_info.get('address'):
                                    break
                    
                    # Extract company name from title or h1
                    if not contact_info.get('company_name'):
                        title = soup.find('title')
                        h1 = soup.find('h1')
                        
                        if title:
                            company_name = title.get_text().strip()
                            # Clean up common title suffixes
                            for suffix in [' - Home', ' | Home', ' Homepage']:
                                company_name = company_name.replace(suffix, '')
                            contact_info['company_name'] = company_name
                        elif h1:
                            contact_info['company_name'] = h1.get_text().strip()
                    
                except Exception as e:
                    continue  # Try next page
            
        except Exception as e:
            logger.error(f"Contact extraction failed for {url}: {str(e)}")
        finally:
            driver.quit()
        
        return contact_info

    async def _classify_industry(self, content_data: Dict) -> str:
        """Classify website industry using AI"""
        try:
            # Prepare content for classification
            text_content = f"Title: {content_data.get('title', '')}\n"
            text_content += f"Description: {content_data.get('description', '')}\n"
            text_content += f"Body text sample: {content_data.get('body_text', '')[:1000]}"
            
            response = await self.openai_client.chat.completions.acreate(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert at classifying business websites. Analyze the content and classify into one of these industries: Technology, E-commerce, Local Business, Professional Services, Healthcare, Finance, Education, Non-profit, Media, Manufacturing, Real Estate, Food & Beverage, Beauty & Wellness, Automotive, Travel & Tourism, Other. Respond with just the industry name."
                    },
                    {
                        "role": "user",
                        "content": text_content
                    }
                ],
                max_tokens=50,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"Industry classification failed: {str(e)}")
            return "Other"

    async def _generate_ai_scores(self, url: str, technical_data: Dict, content_data: Dict) -> Dict[str, int]:
        """Generate CodeRated scores using AI analysis"""
        try:
            # Prepare data for AI analysis
            analysis_prompt = f"""
            Analyze this website and provide scores (0-100) for each category:
            
            URL: {url}
            Title: {content_data.get('title', '')}
            Description: {content_data.get('description', '')}
            
            Technical Data:
            - Lighthouse Performance: {technical_data.get('lighthouse', {}).get('performance', 'N/A')}
            - Accessibility: {technical_data.get('lighthouse', {}).get('accessibility', 'N/A')}
            - SEO Score: {technical_data.get('lighthouse', {}).get('seo', 'N/A')}
            
            Content Analysis:
            - Has proper headings: {bool(content_data.get('headings', {}).get('h1'))}
            - Image count: {len(content_data.get('images', []))}
            - Form count: {content_data.get('forms', 0)}
            - Social media presence: {content_data.get('social_media', {})}
            
            Provide scores for:
            1. UX Design (navigation, layout, usability)
            2. SEO Fundamentals (meta tags, structure, content)
            3. Speed Optimization (load times, performance)
            4. Visual Identity (branding, design consistency)
            5. Strategic Copy (messaging, clarity, conversion)
            
            Return as JSON: {"ux_design": X, "seo_fundamentals": X, "speed_optimization": X, "visual_identity": X, "strategic_copy": X}
            """
            
            response = await self.openai_client.chat.completions.acreate(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are CodeRated's AI analyzer. Provide accurate, detailed website scores based on industry best practices."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt
                    }
                ],
                max_tokens=200,
                temperature=0.3
            )
            
            scores_text = response.choices[0].message.content.strip()
            scores = json.loads(scores_text)
            
            # Ensure all scores are integers between 0-100
            for key in scores:
                scores[key] = max(0, min(100, int(scores[key])))
            
            return scores
            
        except Exception as e:
            logger.error(f"AI scoring failed: {str(e)}")
            # Return default scores if AI fails
            return {
                'ux_design': 70,
                'seo_fundamentals': 65,
                'speed_optimization': 60,
                'visual_identity': 75,
                'strategic_copy': 68
            }

    async def _generate_ai_summary(self, analysis: WebsiteAnalysis) -> Dict[str, str]:
        """Generate human-readable AI summary for outreach"""
        try:
            summary_prompt = f"""
            Create a CodeRated summary for {analysis.domain} (Score: {analysis.score}/100):
            
            Industry: {analysis.industry}
            Company: {analysis.company_name}
            
            Scores:
            - UX Design: {analysis.ux_design}/100
            - SEO: {analysis.seo_fundamentals}/100
            - Speed: {analysis.speed_optimization}/100
            - Visual Identity: {analysis.visual_identity}/100
            - Strategic Copy: {analysis.strategic_copy}/100
            
            Create three sections:
            1. "working" - What's working well (2-3 specific positives)
            2. "improvements" - Where they could improve (2-3 actionable suggestions)
            3. "invitation" - Friendly invitation/insight (1-2 sentences, conversational tone)
            
            Write in a professional but friendly tone, like a helpful consultant.
            Return as JSON: {"working": "...", "improvements": "...", "invitation": "..."}
            """
            
            response = await self.openai_client.chat.completions.acreate(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are CodeRated's AI copywriter. Create engaging, helpful summaries for website outreach that sound natural and consultative."
                    },
                    {
                        "role": "user",
                        "content": summary_prompt
                    }
                ],
                max_tokens=400,
                temperature=0.7
            )
            
            summary_text = response.choices[0].message.content.strip()
            summary = json.loads(summary_text)
            
            return summary
            
        except Exception as e:
            logger.error(f"AI summary generation failed: {str(e)}")
            # Return default summary if AI fails
            return {
                "working": f"The website shows a solid foundation with good basic structure and clear contact information.",
                "improvements": f"There are opportunities to enhance mobile optimization and improve page loading speeds for better user experience.",
                "invitation": f"We'd love to share the full CodeRated analysis with specific recommendations to help boost your online presence!"
            }

    async def _store_analysis(self, analysis: WebsiteAnalysis):
        """Store analysis results in PostgreSQL database"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            # Insert main analysis record
            insert_query = """
            INSERT INTO website_analyses 
            (url, domain, title, description, score, ux_design, seo_fundamentals, 
             speed_optimization, visual_identity, strategic_copy, industry, 
             contact_email, phone, address, company_name, analysis_summary, 
             technical_metrics, created_at) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cur.execute(insert_query, (
                analysis.url, analysis.domain, analysis.title, analysis.description,
                analysis.score, analysis.ux_design, analysis.seo_fundamentals,
                analysis.speed_optimization, analysis.visual_identity, analysis.strategic_copy,
                analysis.industry, analysis.contact_email, analysis.phone, analysis.address,
                analysis.company_name, json.dumps(analysis.analysis_summary),
                json.dumps(analysis.technical_metrics), analysis.timestamp
            ))
            
            conn.commit()
            cur.close()
            conn.close()
            
            logger.info(f"Analysis stored for {analysis.domain}")
            
        except Exception as e:
            logger.error(f"Database storage failed: {str(e)}")

class EmailOutreachManager:
    """Manages automated email outreach campaigns"""
    
    def __init__(self):
        self.smtp_config = {
            'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', '587')),
            'email': os.getenv('SMTP_EMAIL'),
            'password': os.getenv('SMTP_PASSWORD')
        }
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'coderated'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD')
        }

    async def generate_outreach_email(self, analysis: WebsiteAnalysis, template_type: str = 'opportunity') -> Dict[str, str]:
        """Generate personalized outreach email"""
        
        # Email templates
        templates = {
            'opportunity': {
                'subject': 'Quick insights about {domain} - CodeRated analysis',
                'body': '''Hi {first_name},

I just finished analyzing {domain} using our AI-powered website intelligence platform, CodeRated, and wanted to share some quick insights.

Your site scored {score}/100 in our comprehensive review. Here's what stood out:

✅ What's working well:
{working}

🚀 Opportunity areas:
{improvements}

The full analysis covers UX design, SEO fundamentals, speed optimization, visual identity, and strategic copy - with specific recommendations for each area.

Would you be interested in seeing the complete CodeRated report? It's quite detailed and includes actionable steps to boost your online presence.

No strings attached - just thought you might find it valuable.

Best regards,
{sender_name}
CodeRated Team
{sender_email}'''
            },
            'compliment': {
                'subject': 'Impressed by {domain} - CodeRated analysis',
                'body': '''Hi {first_name},

I recently analyzed {domain} using CodeRated, our AI-powered website intelligence platform, and was genuinely impressed!

Your site scored {score}/100 - well above average. Here's what really stood out:

🌟 Exceptional strengths:
{working}

The quality of your web presence is evident, and it's clear you've invested in creating a great user experience.

I'd love to share the full CodeRated analysis with you - it highlights exactly what's working so well and might give you some ideas for future enhancements.

Keep up the excellent work!

Best regards,
{sender_name}
CodeRated Team
{sender_email}'''
            }
        }
        
        template = templates.get(template_type, templates['opportunity'])
        
        # Extract first name from company name or email
        first_name = self._extract_first_name(analysis.contact_email, analysis.company_name)
        
        # Generate personalized content
        email_content = {
            'subject': template['subject'].format(
                domain=analysis.domain,
                first_name=first_name
            ),
            'body': template['body'].format(
                first_name=first_name,
                domain=analysis.domain,
                score=analysis.score,
                working=analysis.analysis_summary.get('working', ''),
                improvements=analysis.analysis_summary.get('improvements', ''),
                sender_name=os.getenv('SENDER_NAME', 'CodeRated Team'),
                sender_email=os.getenv('SENDER_EMAIL', 'team@coderated.ai')
            )
        }
        
        return email_content

    def _extract_first_name(self, email: str, company_name: str) -> str:
        """Extract likely first name from email or company"""
        if email:
            # Try to extract name from email before @
            username = email.split('@')[0]
            # Common patterns: firstname.lastname, firstname_lastname, firstnamelastname
            if '.' in username:
                return username.split('.')[0].title()
            elif '_' in username:
                return username.split('_')[0].title()
            else:
                return username.title()
        
        # Fall back to generic greeting
        return "there"

    async def send_outreach_email(self, to_email: str, subject: str, body: str) -> bool:
        """Send outreach email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['email']
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'])
            server.starttls()
            server.login(self.smtp_config['email'], self.smtp_config['password'])
            
            text = msg.as_string()
            server.sendmail(self.smtp_config['email'], to_email, text)
            server.quit()
            
            # Log email sent
            await self._log_email_sent(to_email, subject)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

    async def _log_email_sent(self, to_email: str, subject: str):
        """Log email sending activity"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            cur.execute("""
                INSERT INTO outreach_emails (to_email, subject, sent_at, status)
                VALUES (%s, %s, %s, %s)
            """, (to_email, subject, datetime.now(), 'sent'))
            
            conn.commit()
            cur.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log email: {str(e)}")

class CampaignManager:
    """Manages automated discovery and outreach campaigns"""
    
    def __init__(self):
        self.analyzer = CodeRatedAnalyzer()
        self.email_manager = EmailOutreachManager()
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'coderated'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD')
        }

    async def run_discovery_campaign(self, campaign_config: Dict):
        """Run automated website discovery and analysis campaign"""
        logger.info("Starting discovery campaign")
        
        # Get campaign parameters
        search_terms = campaign_config.get('search_terms', ['local business', 'small business'])
        max_sites = campaign_config.get('max_sites', 100)
        score_threshold = campaign_config.get('score_threshold', 75)
        email_enabled = campaign_config.get('email_enabled', True)
        
        try:
            # Step 1: Discover websites
            discovered_urls = await self.analyzer.discover_websites(search_terms, max_sites)
            logger.info(f"Discovered {len(discovered_urls)} websites")
            
            # Step 2: Analyze each website
            analyses = []
            for url in discovered_urls:
                try:
                    analysis = await self.analyzer.analyze_website(url)
                    analyses.append(analysis)
                    
                    # Rate limiting - don't overwhelm servers
                    await asyncio.sleep(random.uniform(2, 5))
                    
                except Exception as e:
                    logger.error(f"Failed to analyze {url}: {str(e)}")
                    continue
            
            # Step 3: Filter for outreach candidates
            if email_enabled:
                outreach_candidates = [
                    analysis for analysis in analyses 
                    if analysis.contact_email and analysis.score < score_threshold
                ]
                
                logger.info(f"Found {len(outreach_candidates)} outreach candidates")
                
                # Step 4: Send outreach emails
                for candidate in outreach_candidates:
                    await self._send_outreach_if_qualified(candidate)
                    # Rate limiting for emails
                    await asyncio.sleep(random.uniform(30, 60))
            
            # Step 5: Generate campaign report
            report = await self._generate_campaign_report(analyses, outreach_candidates if email_enabled else [])
            
            logger.info("Campaign completed successfully")
            return report
            
        except Exception as e:
            logger.error(f"Campaign failed: {str(e)}")
            raise

    async def _send_outreach_if_qualified(self, analysis: WebsiteAnalysis):
        """Send outreach email if candidate qualifies"""
        try:
            # Check if we've already contacted this domain
            if await self._already_contacted(analysis.domain):
                logger.info(f"Already contacted {analysis.domain}, skipping")
                return
            
            # Determine email template based on score
            template_type = 'opportunity' if analysis.score < 70 else 'compliment'
            
            # Generate personalized email
            email_content = await self.email_manager.generate_outreach_email(
                analysis, template_type
            )
            
            # Send email
            success = await self.email_manager.send_outreach_email(
                analysis.contact_email,
                email_content['subject'],
                email_content['body']
            )
            
            if success:
                await self._mark_as_contacted(analysis.domain)
                logger.info(f"Outreach sent to {analysis.domain}")
            
        except Exception as e:
            logger.error(f"Outreach failed for {analysis.domain}: {str(e)}")

    async def _already_contacted(self, domain: str) -> bool:
        """Check if we've already contacted this domain"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            cur.execute("""
                SELECT COUNT(*) FROM outreach_emails 
                WHERE to_email LIKE %s AND sent_at > %s
            """, (f'%@{domain}', datetime.now() - timedelta(days=30)))
            
            count = cur.fetchone()[0]
            cur.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking contact history: {str(e)}")
            return False

    async def _mark_as_contacted(self, domain: str):
        """Mark domain as contacted"""
        try:
            conn = psycopg2.connect(**self.db_config)
            cur = conn.cursor()
            
            cur.execute("""
                UPDATE website_analyses 
                SET contacted_at = %s 
                WHERE domain = %s
            """, (datetime.now(), domain))
            
            conn.commit()
            cur.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error marking as contacted: {str(e)}")

    async def _generate_campaign_report(self, analyses: List[WebsiteAnalysis], outreach_sent: List[WebsiteAnalysis]) -> Dict:
        """Generate campaign performance report"""
        if not analyses:
            return {"error": "No analyses completed"}
        
        # Calculate statistics
        total_analyzed = len(analyses)
        average_score = sum(a.score for a in analyses) / total_analyzed
        
        # Score distribution
        score_ranges = {
            'excellent': len([a for a in analyses if a.score >= 90]),
            'good': len([a for a in analyses if 80 <= a.score < 90]),
            'fair': len([a for a in analyses if 70 <= a.score < 80]),
            'poor': len([a for a in analyses if 60 <= a.score < 70]),
            'critical': len([a for a in analyses if a.score < 60])
        }
        
        # Industry breakdown
        industries = {}
        for analysis in analyses:
            industries[analysis.industry] = industries.get(analysis.industry, 0) + 1
        
        # Contact information availability
        with_email = len([a for a in analyses if a.contact_email])
        with_phone = len([a for a in analyses if a.phone])
        
        report = {
            'campaign_summary': {
                'total_analyzed': total_analyzed,
                'average_score': round(average_score, 1),
                'outreach_sent': len(outreach_sent),
                'contact_rate': round((with_email / total_analyzed) * 100, 1) if total_analyzed > 0 else 0
            },
            'score_distribution': score_ranges,
            'industry_breakdown': industries,
            'contact_info': {
                'with_email': with_email,
                'with_phone': with_phone,
                'email_percentage': round((with_email / total_analyzed) * 100, 1) if total_analyzed > 0 else 0
            },
            'top_opportunities': [
                {
                    'domain': a.domain,
                    'score': a.score,
                    'industry': a.industry,
                    'contact_email': a.contact_email
                }
                for a in sorted(analyses, key=lambda x: x.score)[:10]
                if a.contact_email and a.score < 70
            ],
            'timestamp': datetime.now().isoformat()
        }
        
        return report

# Database setup functions
def create_database_tables():
    """Create necessary database tables"""
    
    tables = {
        'website_analyses': '''
            CREATE TABLE IF NOT EXISTS website_analyses (
                id SERIAL PRIMARY KEY,
                url VARCHAR(500) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                title TEXT,
                description TEXT,
                score INTEGER,
                ux_design INTEGER,
                seo_fundamentals INTEGER,
                speed_optimization INTEGER,
                visual_identity INTEGER,
                strategic_copy INTEGER,
                industry VARCHAR(100),
                contact_email VARCHAR(255),
                phone VARCHAR(50),
                address TEXT,
                company_name VARCHAR(255),
                analysis_summary JSONB,
                technical_metrics JSONB,
                contacted_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''',
        'outreach_emails': '''
            CREATE TABLE IF NOT EXISTS outreach_emails (
                id SERIAL PRIMARY KEY,
                to_email VARCHAR(255) NOT NULL,
                subject TEXT,
                body TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'sent',
                opened_at TIMESTAMP,
                replied_at TIMESTAMP
            );
        ''',
        'campaigns': '''
            CREATE TABLE IF NOT EXISTS campaigns (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                config JSONB,
                status VARCHAR(50) DEFAULT 'active',
                results JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
        ''',
        'users': '''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255),
                tier VARCHAR(50) DEFAULT 'observer',
                api_key VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
        '''
    }
    
    try:
        db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'coderated'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD')
        }
        
        conn = psycopg2.connect(**db_config)
        cur = conn.cursor()
        
        for table_name, create_sql in tables.items():
            cur.execute(create_sql)
            logger.info(f"Created/verified table: {table_name}")
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_website_analyses_domain ON website_analyses(domain);",
            "CREATE INDEX IF NOT EXISTS idx_website_analyses_score ON website_analyses(score);",
            "CREATE INDEX IF NOT EXISTS idx_website_analyses_industry ON website_analyses(industry);",
            "CREATE INDEX IF NOT EXISTS idx_outreach_emails_to_email ON outreach_emails(to_email);",
            "CREATE INDEX IF NOT EXISTS idx_outreach_emails_sent_at ON outreach_emails(sent_at);"
        ]
        
        for index_sql in indexes:
            cur.execute(index_sql)
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("Database setup completed successfully")
        
    except Exception as e:
        logger.error(f"Database setup failed: {str(e)}")
        raise

# Main execution functions
async def run_single_analysis(url: str):
    """Analyze a single website"""
    analyzer = CodeRatedAnalyzer()
    return await analyzer.analyze_website(url)

async def run_discovery_campaign(config: Dict = None):
    """Run a full discovery and outreach campaign"""
    if config is None:
        config = {
            'search_terms': ['local business', 'small business', 'restaurant', 'dental practice'],
            'max_sites': 50,
            'score_threshold': 75,
            'email_enabled': True
        }
    
    campaign_manager = CampaignManager()
    return await campaign_manager.run_discovery_campaign(config)

# CLI interface for manual testing
if __name__ == "__main__":
    import argparse
    import asyncio
    
    parser = argparse.ArgumentParser(description='CodeRated Backend Tools')
    parser.add_argument('command', choices=['setup-db', 'analyze', 'campaign'], help='Command to execute')
    parser.add_argument('--url', help='URL to analyze (for analyze command)')
    parser.add_argument('--config', help='JSON config file for campaign')
    
    args = parser.parse_args()
    
    if args.command == 'setup-db':
        create_database_tables()
        print("Database setup completed")
    
    elif args.command == 'analyze':
        if not args.url:
            print("URL required for analyze command")
            exit(1)
        
        async def main():
            result = await run_single_analysis(args.url)
            print(f"Analysis completed for {result.domain}")
            print(f"Score: {result.score}/100")
            print(f"Industry: {result.industry}")
            print(f"Contact: {result.contact_email}")
        
        asyncio.run(main())
    
    elif args.command == 'campaign':
        config = None
        if args.config:
            with open(args.config, 'r') as f:
                config = json.load(f)
        
        async def main():
            result = await run_discovery_campaign(config)
            print("Campaign completed!")
            print(f"Analyzed: {result['campaign_summary']['total_analyzed']} sites")
            print(f"Average score: {result['campaign_summary']['average_score']}")
            print(f"Outreach sent: {result['campaign_summary']['outreach_sent']}")
        
        asyncio.run(main())

# Example usage and configuration
"""
Environment Variables Required:
- OPENAI_API_KEY: Your OpenAI API key
- DB_HOST: PostgreSQL host
- DB_NAME: Database name (coderated)
- DB_USER: Database user
- DB_PASSWORD: Database password
- SMTP_SERVER: SMTP server for email
- SMTP_EMAIL: Email address for sending
- SMTP_PASSWORD: Email password/app password
- SENDER_NAME: Name for email signatures
- SENDER_EMAIL: Reply-to email address

Example campaign config:
{
    "search_terms": ["bakery", "restaurant", "dental", "law firm"],
    "max_sites": 100,
    "score_threshold": 70,
    "email_enabled": true
}

Installation requirements:
pip install asyncio aiohttp psycopg2-binary openai selenium beautifulsoup4 python-whois dnspython

Additional system requirements:
- Google Chrome browser
- ChromeDriver
- Node.js and Lighthouse CLI: npm install -g lighthouse
"""
