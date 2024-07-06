const mysql = require('mysql');

const db = mysql.createConnection({
    host: 'cloudhive-db-prod.ceg1wo1r0hpl.us-east-1.rds.amazonaws.com',
    user: 'chadmin',
    password: 'thiIpmn1kgQF2J0',
    database: 'cloudhive'
});

module.exports = db;
