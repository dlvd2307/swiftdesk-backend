# 🎟️ SwiftDesk

**SwiftDesk** is a lightweight, full-stack ticketing system designed for small teams, solo operators, or internal IT support workflows. It offers user-friendly ticket submission, admin control over ticket status and priority, and a fully deployed cloud architecture.

---

## 🌐 Live Demo

- **Frontend**: [View on Vercel](https://swiftdesk-frontend.vercel.app)
- **Backend**: [API on Render](https://swiftdesk-backend.onrender.com)

---

## ⚙️ Features

### 🧑‍💻 User Capabilities
- Submit tickets with title and description
- Auto-assigned priority (default: Low)
- View real-time ticket status updates

### 🛡️ Admin Capabilities
- Login required for admin access
- View all tickets grouped by status (Open, In Progress, Resolved, Closed)
- Update ticket priority and status with dropdowns
- Filter by priority, search by text, and track who submitted each ticket
- Activity logs automatically track changes

### 🧠 System Highlights
- PostgreSQL-backed persistence (no more data loss on deploy)
- Responsive React frontend
- Flask backend API with secure session management
- Deployed via Vercel (frontend) and Render (backend)

---

## 🧰 Tech Stack

| Layer       | Tech                     |
|-------------|--------------------------|
| Frontend    | React, Axios, Toastify   |
| Backend     | Flask, SQLAlchemy        |
| Database    | PostgreSQL (via Render)  |
| Deployment  | Vercel + Render          |

---

## 🚀 Getting Started

### 1. Clone Repositories

```bash
git clone https://github.com/YOUR_USERNAME/swiftdesk-frontend.git
git clone https://github.com/YOUR_USERNAME/swiftdesk-backend.git
```

---

### 2. Backend Setup

```bash
cd swiftdesk-backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file with:

```
DATABASE_URL=your_postgresql_connection_string
SECRET_KEY=your_flask_secret_key
```

Then run:

```bash
flask run
```

---

### 3. Frontend Setup

```bash
cd swiftdesk-frontend
npm install
```

Create a `.env` file:

```
REACT_APP_API_BASE=http://localhost:5000
```

Then:

```bash
npm start
```

---

## 🔑 Admin Access

Once your backend is live, hit this endpoint **once** to seed the default admin user:

```
https://your-backend-url/seed_admin
```

> **Username**: `admin`  
> **Password**: `password123`

---

## 📌 Future Plans

- Attachments (images, files)
- Email notifications
- Password reset & email verification
- Analytics dashboard (ticket volume trends)
- Better role-based access control

---

## 🤝 Contributions

Forks and pull requests are welcome. SwiftDesk is open to enhancements or customization for your team or workflow.

---

## 🪪 License

MIT © Dylan van Dijk
