const express = require('express');
const { updateUserRole } = require('../controllers/adminController');
const { auth, authorize } = require('../middleware/authMiddleware');
const ROUTES = require('../constants/routeConstants');

const router = express.Router();

router.put(`${ROUTES.USER_ROUTE}/:userId/role`, auth, authorize(['admin']), updateUserRole);

module.exports = router;
