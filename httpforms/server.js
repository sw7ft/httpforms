require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const helmet = require('helmet');
const postmark = require('postmark');
const expressLayouts = require('express-ejs-layouts');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const twilio = require('twilio');
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.set('trust proxy', false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://checkout.stripe.com"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "frame-src": ["'self'", "https://checkout.stripe.com"],
      "form-action": ["'self'", "https://checkout.stripe.com"],
      "connect-src": ["'self'", "https://checkout.stripe.com", "https://api.stripe.com"]
    }
  }
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Origin']
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'httpforms-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.use(express.static(path.join(__dirname, 'public')));

// View engine setup
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.set('layout extractScripts', true);
app.set('layout extractStyles', true);

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// JSON file paths
const usersFilePath = path.join(dataDir, 'users.json');
const formsFilePath = path.join(dataDir, 'forms.json');
const formEntriesFilePath = path.join(dataDir, 'form_entries.json');
const domainsFilePath = path.join(dataDir, 'domains.json');
const subscriptionsFilePath = path.join(dataDir, 'subscriptions.json');

// Initialize JSON files if they don't exist
function initializeJsonFile(filePath, defaultContent = []) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(defaultContent, null, 2));
  }
}

initializeJsonFile(usersFilePath);
initializeJsonFile(formsFilePath);
initializeJsonFile(formEntriesFilePath);
initializeJsonFile(domainsFilePath);
initializeJsonFile(subscriptionsFilePath);

// Helper functions to read and write to JSON files
function readJsonFile(filePath) {
  const data = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(data);
}

function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.isAdmin) {
    return next();
  }
  res.status(403).send('Access denied');
}

// Middleware to check if user has an active subscription
function hasActiveSubscription(req, res, next) {
  try {
    // Allow admins to bypass subscription check
    if (req.session.isAdmin) {
      return next();
    }
    
    // Read subscriptions from file
    const subscriptions = readJsonFile(subscriptionsFilePath);
    
    // Check if user has an active subscription
    const subscription = subscriptions.find(
      s => s.userId === req.session.userId && 
      s.status === 'active' && 
      !s.canceledAt
    );
    
    if (!subscription) {
      // Redirect to plans page if no active subscription
      return res.redirect('/plans');
    }
    
    // Add subscription to request for use in routes
    req.subscription = subscription;
    next();
  } catch (error) {
    console.error('Subscription check error:', error);
    return res.status(500).render('error', { message: 'Failed to check subscription status' });
  }
}

function hasPremiumSubscription(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  const subscriptions = readJsonFile(subscriptionsFilePath);
  const userSubscription = subscriptions.find(s => 
    s.userId === req.session.userId && 
    s.status === 'active' && 
    s.planType === 'premium'
  );
  
  if (!userSubscription) {
    return res.redirect('/plans?upgrade=true');
  }
  
  req.subscription = userSubscription;
  return next();
}

// Routes

// Home page
app.get('/', (req, res) => {
  res.render('index', { 
    user: req.session.userId ? { name: req.session.userName } : null,
    isAdmin: req.session.isAdmin || false
  });
});

// Register page
app.get('/register', (req, res) => {
  res.render('register', { 
    error: null
  });
});

// Register handler
app.post('/register', async (req, res) => {
  try {
    const { name, email, password, confirmPassword, phoneNumber } = req.body;
    
    // Validate input
    if (!name || !email || !password || !confirmPassword) {
      return res.render('register', { 
        error: 'All fields are required'
      });
    }
    
    if (password !== confirmPassword) {
      return res.render('register', { 
        error: 'Passwords do not match'
      });
    }
    
    // Check if user already exists
    const users = readJsonFile(usersFilePath);
    const userExists = users.some(user => user.email === email);
    
    if (userExists) {
      return res.render('register', { 
        error: 'User with this email already exists'
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = {
      id: uuidv4(),
      name,
      email,
      password: hashedPassword,
      phoneNumber: phoneNumber || null,
      isAdmin: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    users.push(newUser);
    writeJsonFile(usersFilePath, users);
    
    // Set session
    req.session.userId = newUser.id;
    req.session.userName = newUser.name;
    req.session.isAdmin = newUser.isAdmin;
    
    // Redirect to plans page
    res.redirect('/plans');
  } catch (error) {
    console.error('Registration error:', error);
    res.render('register', { 
      error: 'Failed to register: ' + error.message
    });
  }
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('login');
});

// Login handler
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.render('login', { error: 'Email and password are required' });
    }
    
    const users = readJsonFile(usersFilePath);
    const user = users.find(user => user.email === email);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    // Set session
    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.isAdmin = user.isAdmin;
    
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'Login failed' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', isAuthenticated, hasActiveSubscription, (req, res) => {
  try {
    const forms = readJsonFile(formsFilePath);
    const userForms = forms.filter(form => form.userId === req.session.userId);
    
    res.render('dashboard', {
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin,
      forms: userForms,
      subscription: req.subscription
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('error', { message: 'Failed to load dashboard' });
  }
});

// Form builder page
app.get('/form/new', isAuthenticated, hasActiveSubscription, (req, res) => {
  res.render('form-builder', {
    user: { name: req.session.userName },
    isAdmin: req.session.isAdmin,
    form: { fields: [] },
    subscription: req.subscription
  });
});

// Edit form page
app.get('/form/edit/:id', isAuthenticated, hasActiveSubscription, (req, res) => {
  try {
    const formId = req.params.id;
    const forms = readJsonFile(formsFilePath);
    const form = forms.find(f => f.id === formId);
    
    if (!form) {
      return res.status(404).render('error', { message: 'Form not found' });
    }
    
    if (form.userId !== req.session.userId && !req.session.isAdmin) {
      return res.status(403).render('error', { message: 'Access denied' });
    }
    
    res.render('form-builder', {
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin,
      form,
      subscription: req.subscription
    });
  } catch (error) {
    console.error('Edit form error:', error);
    res.render('error', { message: 'Failed to load form' });
  }
});

// Create/Update form
app.post('/form/save', isAuthenticated, (req, res) => {
  try {
    const { id, name, fields, domains, notificationEmails } = req.body;
    const forms = readJsonFile(formsFilePath);
    
    // Check if editing an existing form
    if (id) {
      const formIndex = forms.findIndex(f => f.id === id);
      
      if (formIndex === -1) {
        return res.status(404).json({ success: false, message: 'Form not found' });
      }
      
      if (forms[formIndex].userId !== req.session.userId && !req.session.isAdmin) {
        return res.status(403).json({ success: false, message: 'Access denied' });
      }
      
      forms[formIndex] = {
        ...forms[formIndex],
        name,
        fields: JSON.parse(fields),
        domains: domains ? domains.split(',').map(d => d.trim()) : [],
        notificationEmails: notificationEmails ? notificationEmails.split(',').map(e => e.trim()) : [],
        updatedAt: new Date().toISOString()
      };
    } else {
      // Create new form
      const newForm = {
        id: uuidv4(),
        userId: req.session.userId,
        name,
        fields: JSON.parse(fields),
        domains: domains ? domains.split(',').map(d => d.trim()) : [],
        notificationEmails: notificationEmails ? notificationEmails.split(',').map(e => e.trim()) : [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      forms.push(newForm);
    }
    
    writeJsonFile(formsFilePath, forms);
    
    res.json({ success: true, redirect: '/dashboard' });
  } catch (error) {
    console.error('Save form error:', error);
    res.status(500).json({ success: false, message: 'Failed to save form' });
  }
});

// Delete form
app.post('/form/delete/:id', isAuthenticated, (req, res) => {
  try {
    console.log('Delete form request received for ID:', req.params.id);
    const formId = req.params.id;
    const forms = readJsonFile(formsFilePath);
    const formIndex = forms.findIndex(f => f.id === formId);
    
    if (formIndex === -1) {
      console.log('Form not found:', formId);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }
    
    console.log('Form found. User ID:', req.session.userId, 'Form owner:', forms[formIndex].userId);
    if (forms[formIndex].userId !== req.session.userId && !req.session.isAdmin) {
      console.log('Access denied for user', req.session.userId);
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    // Delete form entries as well
    console.log('Deleting form entries for form:', formId);
    const entries = readJsonFile(formEntriesFilePath);
    const updatedEntries = entries.filter(entry => entry.formId !== formId);
    writeJsonFile(formEntriesFilePath, updatedEntries);
    
    // Delete the form
    console.log('Deleting form:', formId);
    forms.splice(formIndex, 1);
    writeJsonFile(formsFilePath, forms);
    
    console.log('Form successfully deleted:', formId);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete form error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete form' });
  }
});

// View form entries
app.get('/form/entries/:id', isAuthenticated, (req, res) => {
  try {
    const formId = req.params.id;
    const forms = readJsonFile(formsFilePath);
    const form = forms.find(f => f.id === formId);
    
    if (!form) {
      return res.status(404).render('error', { message: 'Form not found' });
    }
    
    if (form.userId !== req.session.userId && !req.session.isAdmin) {
      return res.status(403).render('error', { message: 'Access denied' });
    }
    
    const entries = readJsonFile(formEntriesFilePath);
    const formEntries = entries.filter(entry => entry.formId === formId);
    
    res.render('form-entries', {
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin,
      form,
      entries: formEntries
    });
  } catch (error) {
    console.error('View entries error:', error);
    res.render('error', { message: 'Failed to load form entries' });
  }
});

// Domain management (admin only)
app.get('/domains', isAuthenticated, isAdmin, (req, res) => {
  try {
    const domains = readJsonFile(domainsFilePath);
    const forms = readJsonFile(formsFilePath);
    
    res.render('domains', {
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin,
      domains,
      forms
    });
  } catch (error) {
    console.error('Domains error:', error);
    res.render('error', { message: 'Failed to load domains' });
  }
});

// Add/Update domain
app.post('/domain/save', isAuthenticated, isAdmin, (req, res) => {
  try {
    const { id, domain, formIds } = req.body;
    const domains = readJsonFile(domainsFilePath);
    
    if (id) {
      const domainIndex = domains.findIndex(d => d.id === id);
      
      if (domainIndex === -1) {
        return res.status(404).json({ success: false, message: 'Domain not found' });
      }
      
      domains[domainIndex] = {
        ...domains[domainIndex],
        domain,
        formIds: formIds || [],
        updatedAt: new Date().toISOString()
      };
    } else {
      const newDomain = {
        id: uuidv4(),
        domain,
        formIds: formIds || [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      domains.push(newDomain);
    }
    
    writeJsonFile(domainsFilePath, domains);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Save domain error:', error);
    res.status(500).json({ success: false, message: 'Failed to save domain' });
  }
});

// Delete domain
app.post('/domain/delete/:id', isAuthenticated, isAdmin, (req, res) => {
  try {
    const domainId = req.params.id;
    const domains = readJsonFile(domainsFilePath);
    const domainIndex = domains.findIndex(d => d.id === domainId);
    
    if (domainIndex === -1) {
      return res.status(404).json({ success: false, message: 'Domain not found' });
    }
    
    domains.splice(domainIndex, 1);
    writeJsonFile(domainsFilePath, domains);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete domain error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete domain' });
  }
});

// Form submission API
app.post('/api/submit/:formId', async (req, res) => {
  try {
    // Set CORS headers specifically for this endpoint
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Origin');
    
    const formId = req.params.formId;
    const formData = req.body;
    const referer = req.headers.referer || '';
    const domain = new URL(referer).hostname;
    
    const forms = readJsonFile(formsFilePath);
    const form = forms.find(f => f.id === formId);
    
    if (!form) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }
    
    // Check if domain is allowed
    if (form.domains && form.domains.length > 0) {
      const isAllowedDomain = form.domains.some(d => domain.includes(d));
      
      if (!isAllowedDomain) {
        return res.status(403).json({ success: false, message: 'Domain not allowed' });
      }
    }
    
    // Save form entry
    const entries = readJsonFile(formEntriesFilePath);
    const newEntry = {
      id: uuidv4(),
      formId,
      data: formData,
      domain,
      createdAt: new Date().toISOString()
    };
    
    entries.push(newEntry);
    writeJsonFile(formEntriesFilePath, entries);
    
    // Get form owner's details
    const users = readJsonFile(usersFilePath);
    const formOwner = users.find(user => user.id === form.userId);
    
    if (formOwner) {
      // Send email notification if POSTMARK_API_TOKEN is set
      if (process.env.POSTMARK_API_TOKEN) {
        const client = new postmark.ServerClient(process.env.POSTMARK_API_TOKEN);
        
        const formFields = Object.entries(formData)
          .map(([key, value]) => `<p><strong>${key}:</strong> ${value}</p>`)
          .join('');
        
        // Prepare email content
        const emailSubject = `New submission for ${form.name}`;
        const emailHtml = `
          <h1>New form submission</h1>
          <p>You have a new submission for ${form.name} from ${domain}</p>
          <div>${formFields}</div>
        `;
        
        // Send to form owner
        client.sendEmail({
          From: 'forms@httpforms.com',
          To: formOwner.email,
          Subject: emailSubject,
          HtmlBody: emailHtml,
          MessageStream: 'outbound'
        });
        
        // Send to additional notification emails if specified
        if (form.notificationEmails && form.notificationEmails.length > 0) {
          form.notificationEmails.forEach(email => {
            if (email && email.includes('@')) {
              client.sendEmail({
                From: 'forms@httpforms.com',
                To: email,
                Subject: emailSubject,
                HtmlBody: emailHtml,
                MessageStream: 'outbound'
              });
            }
          });
        }
      }
      
      // Check if user has premium subscription and phone number
      const subscriptions = readJsonFile(subscriptionsFilePath);
      const userSubscription = subscriptions.find(sub => 
        sub.userId === form.userId && 
        sub.status === 'active' && 
        sub.planType === 'premium' &&
        !sub.canceledAt
      );
      
      if (userSubscription && formOwner.phoneNumber) {
        // Send SMS notification
        const message = `New submission for ${form.name} from ${domain}. Check your email for details.`;
        await sendSmsNotification(form.userId, message);
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Form submission error:', error);
    res.status(500).json({ success: false, message: 'Failed to submit form' });
  }
});

// Get embed code
app.get('/form/embed/:id', isAuthenticated, (req, res) => {
  try {
    const formId = req.params.id;
    const forms = readJsonFile(formsFilePath);
    const form = forms.find(f => f.id === formId);
    
    if (!form) {
      return res.status(404).render('error', { message: 'Form not found' });
    }
    
    if (form.userId !== req.session.userId && !req.session.isAdmin) {
      return res.status(403).render('error', { message: 'Access denied' });
    }
    
    res.render('embed-code', {
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin,
      form,
      baseUrl: `https://${req.get('host')}`
    });
  } catch (error) {
    console.error('Embed code error:', error);
    res.render('error', { message: 'Failed to generate embed code' });
  }
});

// API to get form structure (for embedding)
app.get('/api/form/:formId', (req, res) => {
  try {
    // Set CORS headers specifically for this endpoint
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Origin');
    
    const formId = req.params.formId;
    const referer = req.headers.referer || '';
    const domain = referer ? new URL(referer).hostname : '';
    
    const forms = readJsonFile(formsFilePath);
    const form = forms.find(f => f.id === formId);
    
    if (!form) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }
    
    // Check if domain is allowed
    if (form.domains && form.domains.length > 0 && domain) {
      const isAllowedDomain = form.domains.some(d => domain.includes(d));
      
      if (!isAllowedDomain) {
        return res.status(403).json({ success: false, message: 'Domain not allowed' });
      }
    }
    
    // Return only necessary form data
    res.json({
      success: true,
      form: {
        id: form.id,
        name: form.name,
        fields: form.fields
      }
    });
  } catch (error) {
    console.error('Get form error:', error);
    res.status(500).json({ success: false, message: 'Failed to get form' });
  }
});

// Add OPTIONS handlers for CORS preflight requests
app.options('/api/form/:formId', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Origin');
  res.sendStatus(204);
});

app.options('/api/submit/:formId', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Origin');
  res.sendStatus(204);
});

// Plans page
app.get('/plans', (req, res) => {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const userSubscription = req.session.userId 
      ? subscriptions.find(s => s.userId === req.session.userId && s.status === 'active')
      : null;
    
    if (userSubscription) {
      return res.redirect('/account#subscription');
    }
    
    res.render('plans', {
      user: req.session.userId ? { name: req.session.userName } : null,
      isAdmin: req.session.isAdmin || false,
      error: null
    });
  } catch (error) {
    console.error('Plans page error:', error);
    res.render('error', { message: 'Failed to load plans' });
  }
});

// Create subscription and then register
app.post('/subscription/create-and-register', async (req, res) => {
  try {
    const { planType } = req.body;
    
    if (!planType || (planType !== 'basic' && planType !== 'premium')) {
      return res.render('plans', { error: 'Invalid plan type selected' });
    }
    
    // Get the appropriate price ID based on plan type
    const priceId = planType === 'basic' 
      ? process.env.STRIPE_BASIC_PRICE_ID 
      : process.env.STRIPE_PREMIUM_PRICE_ID;
    
    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${req.protocol}://${req.get('host')}/subscription/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get('host')}/plans`,
      metadata: {
        planType: planType
      }
    });
    
    res.redirect(session.url);
  } catch (error) {
    console.error('Create subscription and register error:', error);
    res.render('plans', { error: 'Failed to start subscription process: ' + error.message });
  }
});

// Subscription success
app.get('/subscription/success', isAuthenticated, async (req, res) => {
  try {
    const { session_id } = req.query;
    
    if (!session_id) {
      return res.redirect('/plans');
    }
    
    // Retrieve checkout session
    const checkoutSession = await stripe.checkout.sessions.retrieve(session_id);
    
    // Create or update subscription record
    const subscriptions = readJsonFile(subscriptionsFilePath);
    
    // Check if user already has an active subscription
    const existingSubIndex = subscriptions.findIndex(s => 
      s.userId === req.session.userId && s.status === 'active'
    );
    
    if (existingSubIndex >= 0) {
      // Update existing subscription
      subscriptions[existingSubIndex].stripeSubscriptionId = checkoutSession.subscription;
      subscriptions[existingSubIndex].planType = checkoutSession.metadata.planType;
      subscriptions[existingSubIndex].updatedAt = new Date().toISOString();
    } else {
      // Create new subscription
      const newSubscription = {
        id: uuidv4(),
        userId: req.session.userId,
        stripeSubscriptionId: checkoutSession.subscription,
        planType: checkoutSession.metadata.planType,
        status: 'active',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      subscriptions.push(newSubscription);
    }
    
    writeJsonFile(subscriptionsFilePath, subscriptions);
    
    // Redirect to dashboard
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Subscription success error:', error);
    res.render('error', { message: 'Failed to process subscription' });
  }
});

// Account page
app.get('/account', isAuthenticated, (req, res) => {
  try {
    const users = readJsonFile(usersFilePath);
    const user = users.find(u => u.id === req.session.userId);
    
    if (!user) {
      return res.render('error', { message: 'User not found' });
    }
    
    // Get user's subscription
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscription = subscriptions.find(s => 
      s.userId === req.session.userId && 
      s.status === 'active' && 
      !s.canceledAt
    );
    
    res.render('account', {
      user,
      isAdmin: req.session.isAdmin || false,
      subscription: subscription || null
    });
  } catch (error) {
    console.error('Account page error:', error);
    res.render('error', { message: 'Failed to load account page' });
  }
});

// Update user profile
app.post('/account/update', isAuthenticated, async (req, res) => {
  try {
    const { name, email, phoneNumber } = req.body;
    
    if (!name || !email) {
      return res.render('account', { 
        error: 'Name and email are required',
        user: { name: req.session.userName },
        isAdmin: req.session.isAdmin || false
      });
    }
    
    const users = readJsonFile(usersFilePath);
    const userIndex = users.findIndex(u => u.id === req.session.userId);
    
    if (userIndex === -1) {
      return res.render('error', { message: 'User not found' });
    }
    
    // Check if email is already in use by another user
    const emailExists = users.some(u => u.email === email && u.id !== req.session.userId);
    
    if (emailExists) {
      return res.render('account', { 
        error: 'Email is already in use',
        user: users[userIndex],
        isAdmin: req.session.isAdmin || false
      });
    }
    
    // Update user
    users[userIndex].name = name;
    users[userIndex].email = email;
    users[userIndex].phoneNumber = phoneNumber || null;
    users[userIndex].updatedAt = new Date().toISOString();
    
    writeJsonFile(usersFilePath, users);
    
    // Update session
    req.session.userName = name;
    
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscription = subscriptions.find(s => s.userId === req.session.userId && s.status === 'active');
    
    res.render('account', {
      message: 'Profile updated successfully',
      user: users[userIndex],
      isAdmin: req.session.isAdmin || false,
      subscription
    });
  } catch (error) {
    console.error('Update account error:', error);
    res.render('account', { 
      error: 'Failed to update profile',
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// Change password
app.post('/account/password', isAuthenticated, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.render('account', { 
        error: 'All password fields are required',
        user: { name: req.session.userName },
        isAdmin: req.session.isAdmin || false
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.render('account', { 
        error: 'New passwords do not match',
        user: { name: req.session.userName },
        isAdmin: req.session.isAdmin || false
      });
    }
    
    const users = readJsonFile(usersFilePath);
    const userIndex = users.findIndex(u => u.id === req.session.userId);
    
    if (userIndex === -1) {
      return res.render('error', { message: 'User not found' });
    }
    
    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, users[userIndex].password);
    
    if (!passwordMatch) {
      return res.render('account', { 
        error: 'Current password is incorrect',
        user: users[userIndex],
        isAdmin: req.session.isAdmin || false
      });
    }
    
    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    users[userIndex].password = hashedPassword;
    users[userIndex].updatedAt = new Date().toISOString();
    
    writeJsonFile(usersFilePath, users);
    
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscription = subscriptions.find(s => s.userId === req.session.userId && s.status === 'active');
    
    res.render('account', {
      message: 'Password changed successfully',
      user: users[userIndex],
      isAdmin: req.session.isAdmin || false,
      subscription
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.render('account', { 
      error: 'Failed to change password',
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// Upgrade subscription
app.post('/subscription/upgrade', isAuthenticated, async (req, res) => {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscriptionIndex = subscriptions.findIndex(s => 
      s.userId === req.session.userId && s.status === 'active' && s.planType === 'basic'
    );
    
    if (subscriptionIndex === -1) {
      return res.redirect('/plans');
    }
    
    // Redirect to Stripe checkout for the premium plan
    const users = readJsonFile(usersFilePath);
    const user = users.find(u => u.id === req.session.userId);
    
    if (!user) {
      return res.render('error', { message: 'User not found' });
    }
    
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      customer_email: user.email,
      client_reference_id: user.id,
      line_items: [
        {
          price: process.env.STRIPE_PREMIUM_PRICE_ID,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${req.protocol}://${req.get('host')}/subscription/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get('host')}/account#subscription`,
      metadata: {
        userId: user.id,
        planType: 'premium'
      }
    });
    
    res.redirect(session.url);
  } catch (error) {
    console.error('Upgrade subscription error:', error);
    res.render('account', { 
      error: 'Failed to upgrade subscription: ' + error.message,
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// Downgrade subscription
app.post('/subscription/downgrade', isAuthenticated, async (req, res) => {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscriptionIndex = subscriptions.findIndex(s => 
      s.userId === req.session.userId && s.status === 'active' && s.planType === 'premium'
    );
    
    if (subscriptionIndex === -1) {
      return res.redirect('/plans');
    }
    
    // Update subscription type (in a real app, you would also update the Stripe subscription)
    subscriptions[subscriptionIndex].planType = 'basic';
    subscriptions[subscriptionIndex].updatedAt = new Date().toISOString();
    
    writeJsonFile(subscriptionsFilePath, subscriptions);
    
    res.redirect('/account#subscription');
  } catch (error) {
    console.error('Downgrade subscription error:', error);
    res.render('account', { 
      error: 'Failed to downgrade subscription: ' + error.message,
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// Cancel subscription
app.post('/subscription/cancel', isAuthenticated, async (req, res) => {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscriptionIndex = subscriptions.findIndex(s => 
      s.userId === req.session.userId && s.status === 'active'
    );
    
    if (subscriptionIndex === -1) {
      return res.redirect('/plans');
    }
    
    // Mark subscription for cancellation at period end
    const cancelDate = new Date();
    cancelDate.setMonth(cancelDate.getMonth() + 1); // Cancel in 1 month
    
    subscriptions[subscriptionIndex].cancelAt = cancelDate.toISOString();
    subscriptions[subscriptionIndex].updatedAt = new Date().toISOString();
    
    writeJsonFile(subscriptionsFilePath, subscriptions);
    
    res.redirect('/account#subscription');
  } catch (error) {
    console.error('Cancel subscription error:', error);
    res.render('account', { 
      error: 'Failed to cancel subscription: ' + error.message,
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// Reactivate subscription
app.post('/subscription/reactivate', isAuthenticated, async (req, res) => {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscriptionIndex = subscriptions.findIndex(s => 
      s.userId === req.session.userId && 
      s.status === 'active' && 
      s.cancelAt
    );
    
    if (subscriptionIndex === -1) {
      return res.redirect('/plans');
    }
    
    // Remove cancellation date
    delete subscriptions[subscriptionIndex].cancelAt;
    subscriptions[subscriptionIndex].updatedAt = new Date().toISOString();
    
    writeJsonFile(subscriptionsFilePath, subscriptions);
    
    res.redirect('/account#subscription');
  } catch (error) {
    console.error('Reactivate subscription error:', error);
    res.render('account', { 
      error: 'Failed to reactivate subscription: ' + error.message,
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// Billing portal redirect
app.get('/billing-portal', isAuthenticated, async (req, res) => {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscription = subscriptions.find(s => s.userId === req.session.userId);
    
    if (!subscription) {
      return res.redirect('/plans');
    }
    
    const users = readJsonFile(usersFilePath);
    const user = users.find(u => u.id === req.session.userId);
    
    // Create Stripe customer portal session
    const session = await stripe.billingPortal.sessions.create({
      customer: subscription.stripeCustomerId,
      return_url: `${req.protocol}://${req.get('host')}/account#subscription`,
    });
    
    res.redirect(session.url);
  } catch (error) {
    console.error('Billing portal error:', error);
    res.render('account', { 
      error: 'Failed to access billing portal: ' + error.message,
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin || false
    });
  }
});

// SMS notification function for premium users
async function sendSmsNotification(userId, message) {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscription = subscriptions.find(s => 
      s.userId === userId && 
      s.status === 'active' && 
      s.planType === 'premium'
    );
    
    if (!subscription) {
      console.log('User does not have a premium subscription for SMS notifications');
      return;
    }
    
    const users = readJsonFile(usersFilePath);
    const user = users.find(u => u.id === userId);
    
    if (!user || !user.phoneNumber) {
      console.log('User does not have a phone number configured');
      return;
    }
    
    // Send SMS using Twilio
    await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: user.phoneNumber
    });
    
    console.log('SMS notification sent to user:', userId);
  } catch (error) {
    console.error('Error sending SMS notification:', error);
  }
}

// Stripe webhook endpoint to handle subscription events
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    let event;
    
    // Verify webhook signature
    const signature = req.headers['stripe-signature'];
    
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    // Handle the event
    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
        const subscription = event.data.object;
        await handleSubscriptionChange(subscription);
        break;
        
      case 'customer.subscription.deleted':
        const canceledSubscription = event.data.object;
        await handleSubscriptionCanceled(canceledSubscription);
        break;
        
      case 'invoice.paid':
        const invoice = event.data.object;
        await handleInvoicePaid(invoice);
        break;
        
      case 'invoice.payment_failed':
        const failedInvoice = event.data.object;
        await handlePaymentFailed(failedInvoice);
        break;
        
      default:
        console.log(`Unhandled event type ${event.type}`);
    }
    
    // Return a 200 response
    res.json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    return res.status(500).send('Webhook handler failed');
  }
});

/**
 * Handle subscription created or updated
 */
async function handleSubscriptionChange(subscription) {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const existingIndex = subscriptions.findIndex(
      sub => sub.stripeSubscriptionId === subscription.id
    );
    
    if (existingIndex !== -1) {
      // Update existing subscription
      subscriptions[existingIndex].status = subscription.status;
      subscriptions[existingIndex].updatedAt = new Date().toISOString();
      
      // Check if subscription was canceled at period end
      if (subscription.cancel_at_period_end) {
        subscriptions[existingIndex].canceledAt = new Date().toISOString();
      } else if (subscriptions[existingIndex].canceledAt) {
        // Remove canceledAt if subscription was reactivated
        delete subscriptions[existingIndex].canceledAt;
      }
    }
    
    writeJsonFile(subscriptionsFilePath, subscriptions);
  } catch (error) {
    console.error('Error handling subscription change:', error);
  }
}

/**
 * Handle subscription canceled
 */
async function handleSubscriptionCanceled(subscription) {
  try {
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const existingIndex = subscriptions.findIndex(
      sub => sub.stripeSubscriptionId === subscription.id
    );
    
    if (existingIndex !== -1) {
      // Mark as canceled
      subscriptions[existingIndex].status = 'canceled';
      subscriptions[existingIndex].canceledAt = new Date().toISOString();
      subscriptions[existingIndex].updatedAt = new Date().toISOString();
    }
    
    writeJsonFile(subscriptionsFilePath, subscriptions);
  } catch (error) {
    console.error('Error handling subscription cancellation:', error);
  }
}

/**
 * Handle invoice paid
 */
async function handleInvoicePaid(invoice) {
  try {
    if (invoice.subscription) {
      const subscriptions = readJsonFile(subscriptionsFilePath);
      const existingIndex = subscriptions.findIndex(
        sub => sub.stripeSubscriptionId === invoice.subscription
      );
      
      if (existingIndex !== -1) {
        // Ensure subscription is marked as active
        subscriptions[existingIndex].status = 'active';
        subscriptions[existingIndex].updatedAt = new Date().toISOString();
      }
      
      writeJsonFile(subscriptionsFilePath, subscriptions);
    }
  } catch (error) {
    console.error('Error handling invoice paid:', error);
  }
}

/**
 * Handle payment failed
 */
async function handlePaymentFailed(invoice) {
  try {
    if (invoice.subscription) {
      const subscriptions = readJsonFile(subscriptionsFilePath);
      const existingIndex = subscriptions.findIndex(
        sub => sub.stripeSubscriptionId === invoice.subscription
      );
      
      if (existingIndex !== -1) {
        // Mark subscription as past_due
        subscriptions[existingIndex].status = 'past_due';
        subscriptions[existingIndex].updatedAt = new Date().toISOString();
      }
      
      writeJsonFile(subscriptionsFilePath, subscriptions);
    }
  } catch (error) {
    console.error('Error handling payment failure:', error);
  }
}

// Registration success page
app.get('/registration-success', isAuthenticated, (req, res) => {
  try {
    const users = readJsonFile(usersFilePath);
    const user = users.find(u => u.id === req.session.userId);
    
    if (!user) {
      return res.redirect('/login');
    }
    
    const subscriptions = readJsonFile(subscriptionsFilePath);
    const subscription = subscriptions.find(s => s.userId === req.session.userId && s.status === 'active');
    
    res.render('registration-success', {
      user,
      subscription,
      isAdmin: req.session.isAdmin || false
    });
  } catch (error) {
    console.error('Registration success page error:', error);
    res.redirect('/dashboard');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 