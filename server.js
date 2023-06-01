const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const app = express();

var corsOptions = {
    origin: "http://localhost:8081"
};

app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({
    extended: true
}))

const db = require("./app/models");
const Role = db.role;

db.sequelize.drop().then(() => {
    console.log("Drop tables...");
    db.sequelize.sync({ force: false }).then(() => {
        console.log("Drop and re-sync db.");
        initial();
    })
})


function initial() {
    Role.create({
        id: 1,
        name: "user"
    });

    Role.create({
        id: 2,
        name: "admin"
    })

    Role.create({
        id: 3,
        name: "moderator"
    })
}

// routes
require('./app/routes/auth.routes')(app);
require('./app/routes/user.routes')(app);



app.get("/", (req, res) => {
    res.json({
        message: "Welcome to bezkoder application."
    })
})


const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
})