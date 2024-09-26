// App Entrypoint
const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const ROUTES = require('./constants/routeConstants');
require('dotenv').config();
const cors = require('cors');

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

// Authentication Route
app.use(ROUTES.AUTH.BASE, authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
