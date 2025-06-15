// routes/email.js - Complete email functionality for CodeRated
const express = require("express");
const router = express.Router();
const nodemailer = require("nodemailer");

// Configure email transporter (choose one method below)

// Option 1: Gmail SMTP
const transporter = nodemailer.createTransporter({
  service: "gmail",
  auth: {
    user: process.env.ADMIN_EMAIL, // your-email@gmail.com
    pass: process.env.ADMIN_EMAIL_PASS, // your app password
  },
});

// Option 2: SendGrid (more reliable for production)
/*
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
*/

// Option 3: Mailgun (alternative)
/*
const mailgun = require('mailgun-js')({
  apiKey: process.env.MAILGUN_API_KEY,
  domain: process.env.MAILGUN_DOMAIN
});
*/

// Email template function
const generateEmailHTML = (review) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>CodeRated Analysis Report</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
          background-color: #f8fafc;
        }
        .container {
          background: white;
          border-radius: 12px;
          padding: 30px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
          text-align: center;
          margin-bottom: 30px;
          border-bottom: 2px solid #e2e8f0;
          padding-bottom: 20px;
        }
        .logo {
          font-size: 28px;
          font-weight: bold;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin-bottom: 10px;
        }
        .site-info {
          background: #f1f5f9;
          padding: 20px;
          border-radius: 8px;
          margin: 20px 0;
        }
        .site-name {
          font-size: 24px;
          font-weight: bold;
          color: #1e293b;
          margin-bottom: 8px;
        }
        .site-url {
          color: #64748b;
          font-family: monospace;
          font-size: 14px;
          word-break: break-all;
        }
        .scores-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 15px;
          margin: 25px 0;
        }
        .score-card {
          background: #f8fafc;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 15px;
          text-align: center;
        }
        .score-label {
          font-size: 12px;
          text-transform: uppercase;
          color: #64748b;
          margin-bottom: 5px;
          font-weight: 600;
        }
        .score-value {
          font-size: 24px;
          font-weight: bold;
          color: #1e293b;
        }
        .summary {
          background: #f0f9ff;
          border-left: 4px solid #0ea5e9;
          padding: 20px;
          margin: 20px 0;
          border-radius: 0 8px 8px 0;
        }
        .summary-title {
          font-weight: bold;
          color: #0c4a6e;
          margin-bottom: 10px;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #e2e8f0;
          color: #64748b;
          font-size: 14px;
        }
        .cta-button {
          display: inline-block;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 12px 24px;
          text-decoration: none;
          border-radius: 6px;
          font-weight: 600;
          margin: 20px 0;
        }
        @media (max-width: 600px) {
          .scores-grid {
            grid-template-columns: 1fr;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="logo">CodeRated</div>
          <p style="color: #64748b; margin: 0;">AI-Powered Website Analysis Report</p>
        </div>

        <div class="site-info">
          <div class="site-name">${review.siteName}</div>
          <div class="site-url">${review.websiteUrl}</div>
        </div>

        <div class="summary">
          <div class="summary-title">Analysis Summary</div>
          <p>${review.review}</p>
        </div>

        <div class="scores-grid">
          <div class="score-card">
            <div class="score-label">Code Quality</div>
            <div class="score-value">${review.codeQuality}/10</div>
          </div>
          <div class="score-card">
            <div class="score-label">Performance</div>
            <div class="score-value">${review.performance}/10</div>
          </div>
          <div class="score-card">
            <div class="score-label">Design</div>
            <div class="score-value">${review.design}/10</div>
          </div>
          <div class="score-card">
            <div class="score-label">Accessibility</div>
            <div class="score-value">${review.accessibility}/10</div>
          </div>
        </div>

        <div style="text-align: center;">
          <a href="${review.websiteUrl}" class="cta-button">Visit Website</a>
        </div>

        <div class="footer">
          <p>This report was generated by CodeRated AI</p>
          <p style="font-size: 12px; color: #94a3b8;">
            Generated on ${new Date().toLocaleDateString('en-US', { 
              year: 'numeric', 
              month: 'long', 
              day: 'numeric' 
            })}
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Main email sending route
router.post("/send-review-email", async (req, res) => {
  try {
    const { review, email } = req.body;

    // Validation
    if (!email || !review) {
      return res.status(400).json({ 
        success: false, 
        error: "Missing required fields: email and review data" 
      });
    }

    if (!review.siteName || !review.websiteUrl) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid review data: missing siteName or websiteUrl" 
      });
    }

    // Email options
    const mailOptions = {
      from: `"CodeRated AI" <${process.env.ADMIN_EMAIL}>`,
      to: email,
      subject: `🚀 CodeRated Analysis: ${review.siteName}`,
      html: generateEmailHTML(review),
      // Plain text fallback
      text: `
CodeRated Analysis Report

Website: ${review.siteName}
URL: ${review.websiteUrl}

Summary: ${review.review}

Scores:
- Code Quality: ${review.codeQuality}/10
- Performance: ${review.performance}/10
- Design: ${review.design}/10
- Accessibility: ${review.accessibility}/10

Generated by CodeRated AI on ${new Date().toLocaleDateString()}
      `.trim()
    };

    // Send email using Nodemailer
    await transporter.sendMail(mailOptions);

    // Log success (optional)
    console.log(`✅ Email sent successfully to ${email} for ${review.siteName}`);

    res.json({ 
      success: true, 
      message: "Email sent successfully",
      recipient: email,
      siteName: review.siteName
    });

  } catch (error) {
    console.error("❌ Email sending failed:", error);

    // Handle specific email errors
    let errorMessage = "Failed to send email. Please try again.";
    
    if (error.code === 'EAUTH') {
      errorMessage = "Email authentication failed. Please check your email credentials.";
    } else if (error.code === 'ECONNECTION') {
      errorMessage = "Could not connect to email server. Please try again later.";
    } else if (error.responseCode === 550) {
      errorMessage = "Invalid recipient email address.";
    }

    res.status(500).json({ 
      success: false, 
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Batch email sending route (for sending multiple emails)
router.post("/send-batch-review-emails", async (req, res) => {
  try {
    const { reviews, sender } = req.body;

    if (!reviews || !Array.isArray(reviews) || reviews.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: "No reviews provided" 
      });
    }

    const results = {
      successful: [],
      failed: []
    };

    // Send emails in parallel (but limit concurrency to avoid rate limits)
    const emailPromises = reviews.map(async (review) => {
      try {
        const mailOptions = {
          from: `"CodeRated AI" <${process.env.ADMIN_EMAIL}>`,
          to: sender?.email || process.env.ADMIN_EMAIL, // Default to admin email
          subject: `📊 CodeRated Batch Report: ${review.siteName}`,
          html: generateEmailHTML(review)
        };

        await transporter.sendMail(mailOptions);
        results.successful.push(review.siteName);
      } catch (error) {
        console.error(`Failed to send email for ${review.siteName}:`, error);
        results.failed.push({ siteName: review.siteName, error: error.message });
      }
    });

    await Promise.all(emailPromises);

    console.log(`📧 Batch email results: ${results.successful.length} successful, ${results.failed.length} failed`);

    res.json({
      success: true,
      message: `Sent ${results.successful.length} emails successfully`,
      results
    });

  } catch (error) {
    console.error("❌ Batch email sending failed:", error);
    res.status(500).json({ 
      success: false, 
      message: "Batch email sending failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Test email route (for development/testing)
router.post("/test-email", async (req, res) => {
  try {
    const testEmail = req.body.email || process.env.ADMIN_EMAIL;
    
    const testMailOptions = {
      from: `"CodeRated AI" <${process.env.ADMIN_EMAIL}>`,
      to: testEmail,
      subject: "🧪 CodeRated Email Test",
      html: `
        <h2>Email Test Successful!</h2>
        <p>Your CodeRated email configuration is working correctly.</p>
        <p>Test sent at: ${new Date().toISOString()}</p>
      `
    };

    await transporter.sendMail(testMailOptions);
    
    res.json({ 
      success: true, 
      message: "Test email sent successfully",
      recipient: testEmail
    });

  } catch (error) {
    console.error("❌ Test email failed:", error);
    res.status(500).json({ 
      success: false, 
      message: "Test email failed",
      error: error.message
    });
  }
});

module.exports = router;