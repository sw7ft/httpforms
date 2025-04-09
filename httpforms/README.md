# HTTPForms

A powerful and easy-to-use contact form builder and manager that allows you to create custom forms and embed them on your website.

## Features

- **Easy Form Building**: Intuitive drag-and-drop form builder
- **Domain Control**: Specify which domains can use your forms
- **Email Notifications**: Receive instant email notifications for new form submissions
- **Responsive Design**: Mobile-friendly forms that look great on any device
- **Secure Submissions**: Data stored securely and accessible only to authorized users

## Requirements

- Node.js (v14 or higher)
- npm (v6 or higher)

## Installation

1. Clone this repository
2. Install dependencies:

```bash
npm install
```

3. Create `.env` file (you can copy from `.env.example`):

```
PORT=3000
SESSION_SECRET=your-secret-key
POSTMARK_API_TOKEN=your-postmark-token
```

4. Initialize data files:

```bash
npm run setup
```

## Running the Application

### Development Mode

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

The application will run on `http://localhost:3000` by default.

## Usage

1. Register for an account (the first registered user becomes admin)
2. Log in to your dashboard
3. Create a new form using the form builder
4. Copy the embed code and add it to your website
5. Manage form submissions from your dashboard

## Email Notifications

To enable email notifications, set up a Postmark account and add your API token to the `.env` file.

## Security

- All form submissions are stored securely
- Domain verification prevents unauthorized usage of your forms
- Admin controls for managing users and forms

## License

MIT 