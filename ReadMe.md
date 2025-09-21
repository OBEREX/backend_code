# Pefoma Django Backend

A Django monolithic backend with Supabase integration for the Pefoma AI-powered inventory management system. This backend provides authentication, user management, and API endpoints while being modular enough to split into microservices later.

## 🚀 Features

- **Supabase Authentication Integration**: Complete signup, login, and password reset flows
- **JWT Middleware**: Automatic token validation and user attachment
- **Profile Management**: Local Profile sync with Supabase webhooks
- **Email Verification**: Enforced email verification for all protected endpoints
- **Modular Architecture**: Easy to split into microservices later
- **Azure Container Apps Ready**: Configured for Azure deployment
- **Comprehensive Testing**: Unit and integration tests for auth flows

## 🛠 Technology Stack

- **Django 4.2** with Django REST Framework
- **Supabase** for authentication and database
- **PostgreSQL** (via Supabase)
- **Redis** for caching
- **Docker** for containerization
- **Azure Container Apps** for deployment

## 📋 Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Supabase account and project
- Azure account (for deployment)

## 🏗 Setup Instructions

### 1. Clone and Install

```bash
git clone <repository-url>
cd pefoma-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required environment variables:

```env
# Django Settings
DJANGO_SECRET_KEY=your-super-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

# Supabase Configuration  
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
SUPABASE_JWT_SECRET=your-jwt-secret

# Database (Supabase PostgreSQL)
DATABASE_URL=postgresql://user:password@host:port/database
```

### 3. Supabase Setup

1. Apply the canonical SQL schema to your Supabase project:
   ```sql
   -- Run the SQL from the canonical schema artifact
   ```

2. Configure Supabase webhooks (optional but recommended):
   - Go to Database → Webhooks in Supabase Dashboard
   - Create webhook for `auth.users` table
   - URL: `https://your-domain.com/auth/webhook/`
   - Events: INSERT, UPDATE, DELETE

### 4. Database Migration

```bash
# Run migrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

### 5. Running Locally

#### Option A: Django Development Server
```bash
python manage.py runserver
```

#### Option B: Docker Compose
```bash
docker-compose up --build
```

The API will be available at `http://localhost:8000`

## 📚 API Endpoints

### Authentication Endpoints

#### 1. User Signup
**POST** `/auth/signup/`

```bash
curl -X POST http://localhost:8000/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe", 
    "email": "john.doe@example.com",
    "phone": "+1234567890",
    "company": "Acme Corp",
    "business_type": "Technology & Electronics",
    "city": "New York",
    "state": "NY",
    "password": "SecurePass123",
    "confirm_password": "SecurePass123"
  }'
```

**Success Response (201):**
```json
{
  "success": true,
  "message": "Account created successfully. Please check your email to verify your account.",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

#### 2. User Login
**POST** `/auth/login/`

```bash
curl -X POST http://localhost:8000/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePass123"
  }'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "john.doe@example.com",
    "email_confirmed_at": "2024-01-15T10:30:00Z"
  },
  "session": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "expires_in": 3600,
    "expires_at": 1642248600
  }
}
```

#### 3. Forgot Password
**POST** `/auth/forgot-password/`

```bash
curl -X POST http://localhost:8000/auth/forgot-password/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com"