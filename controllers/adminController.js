const User = require('../models/User');

const getAllUsers = async (req, res) => {
  try {
    const users = await User.find({});
    res.status(200).json(users);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const getUser = async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.status(200).json(user);
  } catch (error) {
    return res.status(500).json({ message: 'Server error. Couldnt find user with specified id.' });
  }
};

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

    return res.status(200).json({ message: `User role updated to ${newRole}.` });
  } catch (error) {
    return res.status(500).json({ message: 'Server error. Couldnt update role.' });
  }
};

const deleteUser = async (req, res) => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await user.deleteOne();
    return res.status(200).json({ message: `User ${user.accountName} deleted successfuly.` });
  } catch (error) {
    return res.status(500).json({ message: 'Server error. Couldnt delete user.' });
  }
};

module.exports = { updateUserRole, deleteUser, getAllUsers, getUser };
