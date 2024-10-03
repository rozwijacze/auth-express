const express = require('express');
const { updateUserRole, deleteUser, getAllUsers, getUser } = require('../controllers/adminController');
const { auth, authorize } = require('../middlewares/authMiddleware');
const ROUTES = require('../constants/routeConstants');

const router = express.Router();
router.use(auth, authorize(['admin']));

router.get(`/`, getAllUsers);
router.get(`/:userId`, getUser);
router.put(`/:userId/role`, updateUserRole);
router.delete(`/:userId`, deleteUser);

module.exports = router;
