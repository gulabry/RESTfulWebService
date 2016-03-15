'use strict';

var router = require('express').Router();

module.exports = router;

router.get('/getCurrentUser', function(req, res) {
    
    if (session.user !== undefined) {
        //set email hash for gravitar lookup
        session.user.imageHash = crypto.createHash('md5').update(session.user.email).digest('hex');
        res.send(session.user);
        
    } else {
        res.send({username : "please login again."});  
    }
});