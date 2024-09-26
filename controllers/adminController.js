const User = require('../models/User');

const updateUserRole = async (req, res) => {
  const { userId, newRole } = req.body;

  if (!['user', 'editor', 'admin'].includes(newRole)) {
    return res.status(400).json({ message: 'Invalid role provided' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.role = newRole;
    await user.save();

    return res.status(200).json({ message: `User role updated to ${newRole}` });
  } catch (error) {
    return res.status(500).json({ message: 'Server error' });
  }
};

module.exports = { updateUserRole };
