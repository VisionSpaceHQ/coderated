// README.md
# CodeRated Frontend

Modern React application for the CodeRated AI-powered website intelligence platform.

## 🚀 Quick Start

### Development
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Open http://localhost:3000
```

### Production Build
```bash
# Build for production
npm run build

# Preview production build
npm run preview
```

## 🛠 Tech Stack

- **React 18** - Modern React with hooks
- **Vite** - Fast build tool and dev server
- **CSS3** - Custom glass morphism design system
- **Fetch API** - Native HTTP client
- **Context API** - State management

## 🎨 Design System

### Glass Morphism UI
- **Backdrop blur effects** for depth
- **Gradient overlays** and borders
- **Smooth animations** and transitions
- **Responsive design** for all devices

### Color Palette
- **Primary**: `#6366f1` to `#8b5cf6` gradient
- **Background**: Dark radial gradient
- **Glass**: `rgba(255, 255, 255, 0.02)` with blur
- **Text**: White with opacity variations

## 📁 Project Structure

```
src/
├── components/          # React components
│   ├── Navbar.jsx      # Navigation bar
│   ├── HomePage.jsx    # Main landing page
│   ├── ProfilePage.jsx # User profile
│   ├── SettingsPage.jsx # Settings panel
│   ├── OutreachHub.jsx # Email outreach
│   └── DashboardPage.jsx # Analytics dashboard
├── utils/              # Utility functions
│   ├── auth.jsx       # Authentication context
│   ├── api.js         # API client
│   └── helpers.js     # Helper functions
├── styles/
│   └── global.css     # Global styles
├── App.jsx            # Main app component
└── main.jsx          # App entry point
```

## 🔧 Configuration

### Environment Variables
Create `.env` file:
```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_ENVIRONMENT=development
```

### API Integration
The frontend connects to the CodeRated backend API:
- **Authentication**: JWT-based auth
- **Real-time updates**: WebSocket connection
- **Error handling**: Comprehensive error states
- **Loading states**: Smooth loading experiences

## 🌐 Deployment

### Netlify (Recommended)
1. Connect GitHub repository
2. Set build command: `npm run build`
3. Set publish directory: `dist`
4. Configure environment variables
5. Deploy automatically on push

### Manual Deployment
```bash
# Build production bundle
npm run build

# Upload dist/ folder to your hosting provider
```

## 🎯 Features

### User Authentication
- **Registration/Login** with email
- **JWT token management**
- **Persistent sessions**
- **Role-based access** (Observer/Reviewer/Business)

### Website Analysis
- **Search and discover** websites
- **AI-powered analysis** with scoring
- **Real-time results** display
- **Detailed score breakdowns**

### Outreach Management
- **Lead generation** and filtering
- **Email template** management
- **Campaign tracking**
- **Bulk operations**

### User Dashboard
- **Analytics overview**
- **Claimed websites** management
- **Activity tracking**
- **Performance metrics**

## 📱 Responsive Design

- **Mobile-first** approach
- **Tablet optimization**
- **Desktop enhancement**
- **Touch-friendly** interactions

## ⚡ Performance

- **Code splitting** with dynamic imports
- **Image optimization**
- **Lazy loading** components
- **Efficient re-renders**
- **Caching strategies**

## 🔒 Security

- **XSS protection** with CSP headers
- **HTTPS enforcement**
- **Secure authentication**
- **Input validation**
- **Error boundary** handling

## 📊 Analytics Integration

Ready for:
- **Google Analytics 4**
- **Mixpanel** event tracking
- **Sentry** error monitoring
- **Custom metrics** collection

---

## 📄 License

Copyright © 2025 CodeRated. All rights reserved.

