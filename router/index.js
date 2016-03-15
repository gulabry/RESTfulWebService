var router = require('express').Router();

router.use('/user', require('./user-router'));

module.exports = router;