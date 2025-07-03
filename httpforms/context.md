# HTTPForms - Application Context & Overview

## 🎯 **Application Purpose**
HTTPForms is a SaaS platform that allows users to build custom contact forms and embed them on their websites. It provides a visual form builder, handles submissions, manages notifications, and includes subscription-based pricing with Stripe integration.

## 🏗️ **Architecture Overview**

### **Technology Stack**
- **Backend**: Node.js with Express.js (monolithic architecture)
- **Frontend**: EJS templating with Tailwind CSS
- **Database**: JSON file-based storage (lightweight, no SQL database)
- **Authentication**: Session-based with bcrypt password hashing
- **Payments**: Stripe integration for subscription management
- **Email**: Postmark for email notifications
- **SMS**: Twilio for premium SMS notifications
- **File Storage**: Local filesystem with Multer
- **Security**: Helmet.js, CORS, input validation

### **Project Structure**
```
httpforms/
├── server.js                    # Main application server (1528 lines)
├── package.json                 # Dependencies and scripts
├── data/                        # JSON data storage
│   ├── users.json              # User accounts
│   ├── forms.json              # Form definitions
│   ├── form_entries.json       # Form submissions
│   ├── domains.json            # Domain configurations
│   └── subscriptions.json      # Subscription data
├── views/                       # EJS templates
│   ├── layout.ejs              # Base layout template
│   ├── index.ejs               # Landing page
│   ├── dashboard.ejs           # User dashboard
│   ├── form-builder.ejs        # Form creation interface
│   ├── form-entries.ejs        # Submission viewer
│   ├── embed-code.ejs          # Embed code generator
│   ├── account.ejs             # User account management
│   └── ...                     # Additional pages
├── uploads/                     # File upload storage
└── public/                      # Static assets (CSS, JS)
```

## 🔧 **Core Features**

### **1. Form Builder System**
- **Visual Interface**: Drag-and-drop form field creation
- **Field Types Supported**:
  - Text Field (basic text input)
  - Email Field (with email validation)
  - Textarea (multi-line text)
  - Select Dropdown (single selection)
  - Checkbox (multiple selections)
  - Radio Buttons (single selection)
  - File Upload (single file, multiple file types)
  - **Photo Gallery Upload** (multiple images only) - *newly added*
  - CAPTCHA (math-based and text-based with audio support)

### **2. Form Embedding & Submission**
- **Embed Code Generation**: JavaScript-based embeddable forms
- **CORS Support**: Cross-domain form submissions
- **Domain Restrictions**: Whitelist specific domains
- **Real-time Validation**: Client-side form validation
- **File Upload Support**: Images, documents, archives (10MB limit, 5 files max)
- **CAPTCHA Protection**: Bot protection with accessibility features

### **3. User Management & Authentication**
- **Registration/Login**: bcrypt password hashing
- **Session Management**: Express-session based authentication
- **Role-based Access**: Admin and regular user roles
- **Profile Management**: Account settings and preferences

### **4. Subscription Management**
- **Stripe Integration**: Secure payment processing
- **Two-Tier Pricing**:
  - **Basic Plan ($5/month)**: Up to 10 forms, email notifications
  - **Premium Plan ($10/month)**: Unlimited forms, email + SMS notifications
- **Subscription Controls**: Upgrade, downgrade, cancel, reactivate
- **Billing Portal**: Customer self-service billing

### **5. Notification System**
- **Email Notifications**: Postmark integration for form submissions
- **SMS Notifications**: Twilio integration (Premium only)
- **Multiple Recipients**: Send to multiple notification emails
- **Attachment Support**: File attachments included in notifications

## 🗂️ **Data Models**

### **User Schema**
```json
{
  "id": "uuid",
  "name": "string",
  "email": "string",
  "password": "hashed_string",
  "phoneNumber": "string|null",
  "isAdmin": "boolean",
  "createdAt": "ISO_date",
  "updatedAt": "ISO_date"
}
```

### **Form Schema**
```json
{
  "id": "uuid",
  "userId": "uuid",
  "name": "string",
  "fields": [
    {
      "type": "text|email|textarea|select|checkbox|radio|file|photo-gallery|captcha",
      "label": "string",
      "name": "string",
      "required": "boolean",
      "options": "array", // for select, checkbox, radio
      "captchaType": "string", // for captcha fields
      "difficulty": "string" // for captcha fields
    }
  ],
  "domains": ["string"], // allowed domains
  "notificationEmails": ["string"], // notification recipients
  "createdAt": "ISO_date",
  "updatedAt": "ISO_date"
}
```

### **Form Entry Schema**
```json
{
  "id": "uuid",
  "formId": "uuid",
  "data": "object", // submitted form data
  "attachments": [
    {
      "filename": "string",
      "originalName": "string",
      "size": "number",
      "mimetype": "string",
      "url": "string"
    }
  ],
  "domain": "string", // submission domain
  "ip": "string", // user IP address
  "userAgent": "string", // user browser
  "createdAt": "ISO_date"
}
```

### **Subscription Schema**
```json
{
  "id": "uuid",
  "userId": "uuid",
  "stripeCustomerId": "string",
  "stripeSubscriptionId": "string",
  "planType": "basic|premium",
  "status": "active|canceled|past_due",
  "cancelAt": "ISO_date|null",
  "createdAt": "ISO_date",
  "updatedAt": "ISO_date"
}
```

## 🌐 **API Endpoints**

### **Authentication Routes**
- `GET /` - Landing page
- `GET /login` - Login page
- `POST /login` - Login handler
- `GET /register` - Registration page
- `POST /register` - Registration handler
- `GET /logout` - Logout handler

### **Dashboard & Management**
- `GET /dashboard` - User dashboard (protected)
- `GET /account` - Account settings (protected)
- `POST /account/update` - Update profile (protected)
- `POST /account/password` - Change password (protected)

### **Form Management**
- `GET /form/new` - Create new form page (protected)
- `GET /form/edit/:id` - Edit form page (protected)
- `POST /form/save` - Save form data (protected)
- `POST /form/delete/:id` - Delete form (protected)
- `GET /form/entries/:id` - View form submissions (protected)
- `GET /form/embed/:id` - Get embed code (protected)

### **Public API (for embedded forms)**
- `GET /api/form/:formId` - Get form structure (public, CORS enabled)
- `POST /api/submit/:formId` - Submit form data (public, CORS enabled)
- `OPTIONS /api/form/:formId` - CORS preflight
- `OPTIONS /api/submit/:formId` - CORS preflight

### **Subscription Management**
- `GET /plans` - Subscription plans page
- `POST /subscription/create-and-register` - Create subscription
- `GET /subscription/success` - Payment success handler
- `POST /subscription/upgrade` - Upgrade subscription (protected)
- `POST /subscription/downgrade` - Downgrade subscription (protected)
- `POST /subscription/cancel` - Cancel subscription (protected)
- `POST /subscription/reactivate` - Reactivate subscription (protected)
- `GET /billing-portal` - Stripe billing portal (protected)

### **Admin Routes**
- `GET /domains` - Domain management (admin only)
- `POST /domain/add` - Add domain (admin only)
- `POST /domain/remove` - Remove domain (admin only)

### **File & Webhook Endpoints**
- `GET /uploads/:filename` - Serve uploaded files
- `POST /stripe-webhook` - Stripe webhook handler

## 🔒 **Security Features**

### **Authentication & Authorization**
- **Password Security**: bcrypt hashing with salt rounds
- **Session Management**: Secure session configuration
- **Route Protection**: Middleware-based access control
- **Admin Privileges**: Role-based permissions
- **Subscription Enforcement**: Plan-based feature restrictions

### **Input Validation & Protection**
- **CAPTCHA Verification**: Math and text-based challenges
- **Domain Restrictions**: Whitelist authorized domains
- **File Upload Limits**: Size and type restrictions
- **Input Sanitization**: XSS protection
- **CORS Configuration**: Controlled cross-origin access

### **Data Protection**
- **Secure File Storage**: Local filesystem with access control
- **Environment Variables**: Secure credential management
- **Webhook Verification**: Stripe signature validation
- **Error Handling**: Comprehensive error management

## 📊 **Key Business Logic**

### **Form Creation Workflow**
1. User creates account and selects subscription plan
2. User builds form using visual form builder
3. System generates unique form ID and embed code
4. User embeds form on their website
5. Form submissions are captured and notifications sent

### **Subscription Enforcement**
- **Basic Plan**: Limited to 10 forms, email notifications only
- **Premium Plan**: Unlimited forms, email + SMS notifications
- **Free Users**: Redirected to plans page
- **Admin Users**: Bypass all restrictions

### **File Upload Process**
1. Files validated for type and size
2. Unique filenames generated with UUID
3. Files stored in `/uploads` directory
4. File metadata stored with form submission
5. Files served with access control

### **CAPTCHA System**
- **Math-based**: Arithmetic problems with difficulty levels
- **Text-based**: Reverse spelling challenges
- **Audio Support**: Speech synthesis for accessibility
- **Server-side Validation**: Prevents bypass attempts

## 🚀 **Recent Enhancements**

### **Photo Gallery Upload Field**
- **Multiple Image Selection**: Users can select multiple photos
- **Image-only Filter**: Restricts to image file types (JPEG, PNG, GIF)
- **Visual Distinction**: Separate from general file upload
- **Backward Compatibility**: Existing file upload field preserved

### **View Details Modal**
- **Enhanced Form Entries**: Modal displays submission details
- **Attachment Support**: Shows uploaded files with download links
- **Responsive Design**: Works on mobile and desktop
- **Debug Features**: Console logging for troubleshooting

### **Subscription Bug Fixes**
- **Account Page Error**: Fixed missing subscription variable
- **Template Consistency**: All account routes now pass subscription data
- **Error Handling**: Improved error messages and fallbacks

## 🔧 **Development Notes**

### **Code Organization**
- **Monolithic Architecture**: All logic in single server.js file
- **Middleware Pattern**: Authentication, authorization, and subscription checks
- **Template-based UI**: EJS templates with shared layout
- **JSON Data Storage**: File-based database for simplicity

### **Performance Considerations**
- **File Upload Limits**: 10MB per file, 5 files per form
- **Session Storage**: Memory-based sessions (consider Redis for production)
- **Static Assets**: Served directly by Express
- **Database Queries**: In-memory JSON operations

### **Production Recommendations**
1. **Database Migration**: Move to PostgreSQL or MongoDB
2. **File Storage**: Implement cloud storage (AWS S3, Google Cloud)
3. **Session Store**: Use Redis for session management
4. **Load Balancing**: Multiple server instances
5. **Monitoring**: Application performance monitoring
6. **Backup Strategy**: Regular data backups
7. **CDN**: Content delivery network for static assets

## 🐛 **Known Limitations**

1. **Scalability**: JSON file storage not suitable for high traffic
2. **Concurrency**: File-based database has race condition risks
3. **File Storage**: Local filesystem not scalable
4. **Session Management**: Memory-based sessions don't persist across restarts
5. **Error Recovery**: Limited backup and recovery mechanisms

## 📈 **Future Enhancement Opportunities**

1. **Advanced Form Fields**: Date pickers, number inputs, file type restrictions
2. **Analytics Dashboard**: Form submission analytics and reporting
3. **Webhook Integration**: Custom webhook endpoints for form submissions
4. **API Improvements**: REST API for programmatic access
5. **Mobile App**: Native mobile app for form management
6. **Team Collaboration**: Multi-user form editing and permissions
7. **Advanced Notifications**: Slack, Discord, custom webhook integrations
8. **Form Templates**: Pre-built form templates for common use cases

## 🔧 **Environment Variables Required**

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

## 📚 **Dependencies Overview**

### **Core Dependencies**
- **express**: Web application framework
- **ejs**: Template engine
- **express-ejs-layouts**: Layout support for EJS
- **express-session**: Session management
- **bcrypt**: Password hashing
- **uuid**: Unique ID generation
- **multer**: File upload handling
- **cors**: Cross-origin resource sharing
- **helmet**: Security middleware

### **Third-party Services**
- **stripe**: Payment processing
- **postmark**: Email delivery
- **twilio**: SMS notifications
- **tailwindcss**: CSS framework

### **Development**
- **nodemon**: Development server with auto-reload

This context document provides a comprehensive overview of the HTTPForms application, its architecture, features, and technical implementation details. It serves as a reference for developers working on the project and understanding its capabilities and limitations. 