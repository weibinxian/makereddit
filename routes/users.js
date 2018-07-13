const express = require('express');

const router = express.Router();
const User = require('../models/user');
const auth = require('./helpers/auth');


// User index
router.get('/', auth.requireLogin, (req, res) => {
  User.find({}, 'username', (err, users) => {
    if (err) {
      console.error(err);
    } else {
      res.render('users/index', { users }); // {{users : users }}
    }
  });
});

// User New
router.get('/new', (req, res) => {
  res.render('users/new');
});

// User create
router.post('/', (req, res) => {
  //
  const user = new User(req.body);

  user.save(function(err, user) {
    if(err) console.log(err);
    return res.redirect('/users');
  });

});

module.exports = router;
