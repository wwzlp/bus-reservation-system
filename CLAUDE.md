# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **bus reservation management system** built with Python Flask backend and vanilla HTML/CSS/JavaScript frontend. The system handles both user-side reservations and admin management, with features like real-time seat availability, violation tracking, and appeal processing.

## Architecture

### Backend Structure (app.py)
- **Framework**: Flask with RESTful API endpoints
- **Database**: SQLite3 with 5 main tables (users, bus_routes, reservations, violations, appeals)
- **Authentication**: JWT tokens with Flask-JWT-Extended
- **Security**: bcrypt password hashing, parameter validation
- **CORS**: Enabled for cross-origin requests

### Frontend Structure
- **User Interface**: `public/index.html` - reservation system for students
- **Admin Interface**: `public/admin.html` - management dashboard for administrators
- **Static Assets**: Served directly from `/public` directory

## Key Components

### Database Schema
- **users**: User accounts with violation/cancel counters and ban status
- **bus_routes**: Route definitions with capacity, schedule, and active status
- **reservations**: Booking records with status tracking and boarding codes
- **violations**: Records of user violations (no-show, cancellations)
- **appeals**: User appeals for account restoration

### Core Business Logic
- **Reservation Rules**: 72-hour advance booking window, 30-min confirmation window
- **Violation System**: 3 violations or 6 cancellations triggers account ban
- **Seat Management**: Real-time availability calculation on booking
- **Appeal Process**: Users can appeal bans, admins can restore accounts

## Development Commands

### Setup & Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database (auto-created on first run)
python app.py
```

### Running the Application
```bash
# Start development server
python app.py

# Access points:
# User interface: http://localhost:8000
# Admin interface: http://localhost:8000/admin
# Default admin: admin/admin123
```

### Database Operations
```bash
# Database file: bus_reservation.db
# Schema defined in init_database() function
# Tables: users, bus_routes, reservations, violations, appeals
```

## API Endpoints

### User Endpoints
- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `GET /api/routes/<date>` - Available routes for date
- `POST /api/reservations` - Create reservation
- `GET /api/my-reservations` - User's reservations
- `PUT /api/reservations/:id/cancel` - Cancel reservation
- `PUT /api/reservations/:id/confirm` - Confirm boarding
- `POST /api/appeals` - Submit appeal

### Admin Endpoints
- `GET /api/admin/routes` - All routes
- `POST /api/admin/routes` - Add route
- `PUT /api/admin/routes/:id` - Update route
- `GET /api/admin/reservations` - All reservations
- `GET /api/admin/appeals` - All appeals
- `PUT /api/admin/appeals/:id` - Process appeal
- `POST /api/admin/check-violations` - Check for violations

## Key Functions to Know

### Backend Core Functions
- `init_database()` - Sets up schema and default admin
- `generate_boarding_code()` - Creates 8-char alphanumeric codes
- JWT decorators for auth: `@jwt_required()` 
- Database helper: `get_db_connection()`

### Business Logic Timing
- **Booking Window**: 72 hours before departure
- **Cancellation**: Before 7:30 AM on departure day
- **Confirmation**: Within 30 minutes of departure
- **Violation Processing**: Manual via admin endpoint

## Configuration
- **Port**: 8000 (hardcoded)
- **JWT Secret**: 'bus-reservation-system-secret-key-2025'
- **Database**: bus_reservation.db (SQLite)
- **Static Files**: /public directory