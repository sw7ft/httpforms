# HTTPForms - Custom Form Builder Platform

HTTPForms is a subscription-based form builder platform that allows users to create custom forms and embed them on their websites. The platform provides an intuitive form builder, real-time notifications, and robust form management capabilities.

## 🚀 Features

### Core Functionality
- **Visual Form Builder**: Drag-and-drop interface for creating custom forms
- **Multiple Field Types**: Text, email, textarea, select, checkbox, radio buttons, and CAPTCHA
- **Custom CAPTCHA**: Built-in math-based and text-based CAPTCHA system with audio accessibility
- **Form Embedding**: Generate embed codes for seamless website integration
- **Real-time Notifications**: Email and SMS notifications for form submissions
- **Domain Restrictions**: Control which domains can use your forms
- **Additional Notification Emails**: Send form submissions to multiple recipients

### Subscription Plans
- **Basic Plan ($5/month)**:
  - Unlimited form submissions
  - Up to 10 forms
  - Email notifications
  
- **Premium Plan ($10/month)**:
  - Unlimited form submissions
  - Unlimited forms
  - Email notifications
  - SMS notifications via Twilio

### Security Features
- **Session-based Authentication**: Secure user login and session management
- **Domain Validation**: Prevent unauthorized form usage
- **CAPTCHA Protection**: Built-in spam protection with accessibility support
- **Input Sanitization**: Protected against common web vulnerabilities

## 📁 Application Structure

```
httpforms/
├── server.js                 # Main Express.js server
├── package.json              # Node.js dependencies
├── .env                      # Environment variables
├── data/                     # JSON data storage
│   ├── users.json           # User accounts
│   ├── forms.json           # Form definitions
│   ├── form_entries.json    # Form submissions
│   ├── domains.json         # Domain configurations
│   └── subscriptions.json   # Subscription data
├── views/                    # EJS templates
│   ├── layout.ejs           # Base layout template
│   ├── index.ejs            # Landing page
│   ├── login.ejs            # Login page
│   ├── register.ejs         # Registration page
│   ├── dashboard.ejs        # User dashboard
│   ├── form-builder.ejs     # Form creation/editing
│   ├── form-entries.ejs     # Form submission viewer
│   ├── embed-code.ejs       # Embed code generator
│   ├── plans.ejs            # Subscription plans
│   └── account.ejs          # Account management
└── public/                   # Static assets
    ├── css/
    ├── js/
    └── images/
```

## 🛠 Technical Stack

- **Backend**: Node.js with Express.js
- **Frontend**: EJS templating with Tailwind CSS
- **Database**: JSON file-based storage
- **Authentication**: bcrypt password hashing with express-session
- **Payments**: Stripe integration for subscriptions
- **Email**: Postmark for email notifications
- **SMS**: Twilio for premium SMS notifications
- **Security**: Helmet.js for security headers, CORS enabled

## ⚙️ Setup Instructions

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn
- Stripe account (for payments)
- Postmark account (for emails)
- Twilio account (for SMS, optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd httpforms
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   Create a `.env` file in the root directory:
   ```env
   # Server Configuration
   PORT=3000
   SESSION_SECRET=your-session-secret-key
   
   # Stripe Configuration
   STRIPE_SECRET_KEY=sk_test_...
   STRIPE_BASIC_PRICE_ID=price_...
   STRIPE_PREMIUM_PRICE_ID=price_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   
   # Email Configuration (Postmark)
   POSTMARK_API_TOKEN=your-postmark-token
   
   # SMS Configuration (Twilio)
   TWILIO_ACCOUNT_SID=your-twilio-sid
   TWILIO_AUTH_TOKEN=your-twilio-token
   TWILIO_PHONE_NUMBER=+1234567890
   ```

4. **Start the application**
   ```bash
   npm start
   ```

5. **Access the application**
   Open your browser to `http://localhost:3000`

## 🏗 Architecture Overview

### Server Architecture (server.js)

#### Middleware Stack
- **Security**: Helmet.js for security headers
- **CORS**: Cross-origin resource sharing for form embedding
- **Body Parsing**: JSON and URL-encoded data handling
- **Sessions**: Express-session for user authentication
- **Static Files**: Serving CSS, JS, and image assets

#### Authentication System
- **Registration**: bcrypt password hashing
- **Login**: Session-based authentication
- **Authorization**: Route-level middleware for protected resources
- **Admin Access**: Special permissions for administrative features

#### Data Management
- **JSON File Storage**: Lightweight file-based database
- **CRUD Operations**: Create, read, update, delete for all entities
- **Data Validation**: Input sanitization and validation
- **Error Handling**: Comprehensive error management

### Form Builder System

#### Field Types Supported
1. **Text Field**: Basic text input
2. **Email Field**: Email validation
3. **Textarea**: Multi-line text input
4. **Select Dropdown**: Single selection from options
5. **Checkbox**: Multiple selections
6. **Radio Buttons**: Single selection from options
7. **CAPTCHA**: Security verification with multiple options

#### CAPTCHA Implementation
- **Math-based**: Simple arithmetic problems (configurable difficulty)
- **Text-based**: Reverse spelling challenges
- **Audio Support**: Speech synthesis for accessibility
- **Difficulty Levels**: Easy, medium, hard configurations

### Subscription Management

#### Stripe Integration
- **Checkout Sessions**: Secure payment processing
- **Webhook Handling**: Real-time subscription updates
- **Plan Management**: Upgrade/downgrade functionality
- **Billing Portal**: Customer self-service billing

#### Plan Enforcement
- **Form Limits**: Basic plan limited to 10 forms
- **Feature Access**: Premium features restricted by plan
- **SMS Notifications**: Premium-only feature

### Form Embedding System

#### Embed Code Generation
- **Dynamic JavaScript**: Self-contained form renderer
- **CORS Support**: Cross-domain form submissions
- **Responsive Design**: Mobile-friendly form styling
- **Real-time Validation**: Client-side form validation

#### Security Features
- **Domain Whitelisting**: Restrict form usage to specific domains
- **CAPTCHA Validation**: Server-side verification
- **Input Sanitization**: Protection against malicious input

## 📊 Data Models

### User Schema
```json
{
  "id": "uuid",
  "name": "string",
  "email": "string",
  "password": "hashed_string",
  "phoneNumber": "string",
  "isAdmin": "boolean",
  "createdAt": "ISO_date",
  "updatedAt": "ISO_date"
}
```

### Form Schema
```json
{
  "id": "uuid",
  "userId": "uuid",
  "name": "string",
  "fields": [
    {
      "id": "string",
      "type": "string",
      "label": "string",
      "name": "string",
      "placeholder": "string",
      "required": "boolean",
      "options": ["array"],
      "difficulty": "string",
      "mathOnly": "boolean",
      "enableAudio": "boolean"
    }
  ],
  "domains": ["array"],
  "notificationEmails": ["array"],
  "createdAt": "ISO_date",
  "updatedAt": "ISO_date"
}
```

### Subscription Schema
```json
{
  "id": "uuid",
  "userId": "uuid",
  "stripeSubscriptionId": "string",
  "planType": "basic|premium",
  "status": "active|canceled|past_due",
  "cancelAt": "ISO_date",
  "createdAt": "ISO_date",
  "updatedAt": "ISO_date"
}
```

## 🔧 API Endpoints

### Authentication Routes
- `POST /register` - User registration
- `POST /login` - User login
- `GET /logout` - User logout

### Form Management
- `GET /form/new` - Create new form page
- `GET /form/edit/:id` - Edit form page
- `POST /form/save` - Save form data
- `POST /form/delete/:id` - Delete form
- `GET /form/entries/:id` - View form submissions
- `GET /form/embed/:id` - Get embed code

### Public API (for embedded forms)
- `GET /api/form/:formId` - Get form structure
- `POST /api/submit/:formId` - Submit form data
- `OPTIONS /api/form/:formId` - CORS preflight
- `OPTIONS /api/submit/:formId` - CORS preflight

### Subscription Management
- `GET /plans` - Subscription plans page
- `POST /subscription/create-and-register` - Create subscription
- `GET /subscription/success` - Payment success handler
- `POST /subscription/upgrade` - Upgrade subscription
- `POST /subscription/downgrade` - Downgrade subscription
- `POST /subscription/cancel` - Cancel subscription
- `POST /subscription/reactivate` - Reactivate subscription

### Webhook Endpoints
- `POST /stripe-webhook` - Stripe webhook handler

## 🎨 Frontend Architecture

### Template System (EJS)
- **Layout Template**: Shared header, navigation, and footer
- **Component Reuse**: Consistent styling and functionality
- **Dynamic Content**: Server-side data injection
- **Client-side Scripts**: Enhanced interactivity

### Styling (Tailwind CSS)
- **Utility-first**: Rapid UI development
- **Responsive Design**: Mobile-first approach
- **Custom Components**: Reusable UI elements
- **Color Scheme**: Primary blue, accent yellow theme

### JavaScript Features
- **Form Builder**: Interactive form creation
- **Real-time Preview**: Live form preview
- **CAPTCHA Generation**: Dynamic challenge creation
- **Audio Support**: Speech synthesis integration
- **CSV Export**: Client-side data export

## 🔒 Security Considerations

### Authentication & Authorization
- **Password Hashing**: bcrypt with salt rounds
- **Session Security**: Secure session configuration
- **Route Protection**: Middleware-based access control
- **Admin Privileges**: Elevated permissions system

### Input Validation
- **Server-side Validation**: All inputs validated on server
- **CAPTCHA Verification**: Bot protection
- **Domain Restrictions**: Prevent unauthorized usage
- **XSS Protection**: Input sanitization

### Payment Security
- **Stripe Integration**: PCI-compliant payment processing
- **Webhook Verification**: Signature validation
- **Secure Endpoints**: HTTPS enforcement

## 🚀 Deployment

### Production Considerations
1. **Environment Variables**: Secure credential management
2. **Database Migration**: Consider PostgreSQL/MongoDB for production
3. **File Storage**: Implement cloud storage for scalability
4. **Load Balancing**: Multiple server instances
5. **Monitoring**: Application performance monitoring
6. **Backup Strategy**: Regular data backups

### Recommended Production Stack
- **Hosting**: Heroku, AWS, or DigitalOcean
- **Database**: PostgreSQL or MongoDB
- **File Storage**: AWS S3 or Google Cloud Storage
- **CDN**: CloudFlare for static assets
- **Monitoring**: New Relic or DataDog

## 📝 Development Workflow

### Code Organization
- **Modular Structure**: Separated concerns
- **Error Handling**: Comprehensive try-catch blocks
- **Logging**: Console logging for debugging
- **Comments**: Well-documented code

### Testing Considerations
- **Unit Tests**: Individual function testing
- **Integration Tests**: API endpoint testing
- **E2E Tests**: Full user workflow testing
- **Security Tests**: Vulnerability scanning

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For support and questions, please contact the development team or create an issue in the repository.

---

**HTTPForms** - Making form creation simple and powerful for everyone. 