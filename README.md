# Project Setup Instructions

## Frontend Setup
```bash
cd frontend
# Install required dependencies
npm install
# Start the development server
npm run dev
```

## Environment Configuration
```bash
# In the backend directory
cp env.example .env
```

### Generate Random Session Secret
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Add the following to your `.env` file:
```
TWITTER_CLIENT_ID=your_client_id_here
TWITTER_CLIENT_SECRET=your_client_secret_here
TWITTER_CALLBACK_URL=http://localhost:3000/auth/twitter/callback
MONGODB_URI=mongodb://localhost:27017/twitter_oauth
SESSION_SECRET=your_random_secret_here
```

## Start Backend Server
```bash
# In the backend directory
node server.js
```