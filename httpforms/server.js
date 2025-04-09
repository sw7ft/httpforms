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

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.set('trust proxy', false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"]
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
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('register');
});

// Register handler
app.post('/register', async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;
    
    // Validation
    if (!name || !email || !password || !confirmPassword) {
      return res.render('register', { error: 'All fields are required' });
    }
    
    if (password !== confirmPassword) {
      return res.render('register', { error: 'Passwords do not match' });
    }
    
    const users = readJsonFile(usersFilePath);
    
    // Check if user already exists
    if (users.some(user => user.email === email)) {
      return res.render('register', { error: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = {
      id: uuidv4(),
      name,
      email,
      password: hashedPassword,
      isAdmin: users.length === 0, // First user is admin
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    writeJsonFile(usersFilePath, users);
    
    // Set session
    req.session.userId = newUser.id;
    req.session.userName = newUser.name;
    req.session.isAdmin = newUser.isAdmin;
    
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Registration error:', error);
    res.render('register', { error: 'Registration failed' });
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
app.get('/dashboard', isAuthenticated, (req, res) => {
  try {
    const forms = readJsonFile(formsFilePath);
    const userForms = forms.filter(form => form.userId === req.session.userId);
    
    res.render('dashboard', {
      user: { name: req.session.userName },
      isAdmin: req.session.isAdmin,
      forms: userForms
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('error', { message: 'Failed to load dashboard' });
  }
});

// Form builder page
app.get('/form/new', isAuthenticated, (req, res) => {
  res.render('form-builder', {
    user: { name: req.session.userName },
    isAdmin: req.session.isAdmin,
    form: { fields: [] }
  });
});

// Edit form page
app.get('/form/edit/:id', isAuthenticated, (req, res) => {
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
      form
    });
  } catch (error) {
    console.error('Edit form error:', error);
    res.render('error', { message: 'Failed to load form' });
  }
});

// Create/Update form
app.post('/form/save', isAuthenticated, (req, res) => {
  try {
    const { id, name, fields, domains } = req.body;
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
app.post('/api/submit/:formId', (req, res) => {
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
    
    // Send email notification if POSTMARK_API_TOKEN is set
    if (process.env.POSTMARK_API_TOKEN) {
      const client = new postmark.ServerClient(process.env.POSTMARK_API_TOKEN);
      
      const users = readJsonFile(usersFilePath);
      const formOwner = users.find(user => user.id === form.userId);
      
      if (formOwner) {
        const formFields = Object.entries(formData)
          .map(([key, value]) => `<p><strong>${key}:</strong> ${value}</p>`)
          .join('');
        
        client.sendEmail({
          From: 'contact@httpforms.com',
          To: formOwner.email,
          Subject: `New submission for ${form.name}`,
          HtmlBody: `
            <h1>New form submission</h1>
            <p>You have a new submission for ${form.name} from ${domain}</p>
            <div>${formFields}</div>
          `,
          MessageStream: 'outbound'
        });
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

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 