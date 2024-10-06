// App Entrypoint
const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const ROUTES = require('./constants/routeConstants');
require('dotenv').config();
const cors = require('cors');
const cookieParser = require('cookie-parser');
const app = express();

app.use(cors());

// app.use(cors({
//   origin: 'http://localhost:4200',
//   methods: ['GET', 'POST'],
//   allowedHeaders: ['Content-Type', 'Authorization']
// }));

connectDB();

// Middlewares
app.use(express.json());

app.use(cookieParser());

// API Routes
app.use(ROUTES.AUTH.BASE, authRoutes);
app.use(ROUTES.USER.BASE, adminRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
