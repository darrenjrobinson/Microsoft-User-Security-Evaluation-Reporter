var express = require('express');
var router = express.Router();

var myLogFunction = function(severity,origin,message) {
  console.log(severity.toUpperCase() + ' ' + origin + ' ' + message);
};

/* GET - console page */
router.get('/', function(req, res, next) {
  res.sendFile('console.html', { root: './public'});
});

module.exports = router;
