const db = require("../models");
const config = require("../config/auth.config");
const User = db.user;
const Role = db.role;
const RefreshToken = db.refreshToken;

const Op = db.Sequelize.Op;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
	// Save User to Database
	User.create({
		username: req.body.username,
		email: req.body.email,
		password: bcrypt.hashSync(req.body.password, 8)
	})
	.then(user => {
		if (req.body.roles) {
			Role.findAll({
				where: {
					name: {
						[Op.or]: req.body.roles
					}
				}
			}).then(roles => {
				user.setRoles(roles).then(() => {
					res.send({ message: "User was registered successfully!" });
				});
			});
		} else {
			// user role = 1
			user.setRoles([1]).then(() => {
				res.send({ message: "User was registered successfully!" });
			});
		}
	})
	.catch(err => {
		res.status(500).send({ message: err.message });
	});
};

exports.signin = (req, res) => {
	User.findOne({
		where: {
			username: req.body.username
		}
	})
	.then(async (user) => {
		if (!user) {
			return res.status(404).send({ message: "User Not found." });
		}

		var passwordIsValid = bcrypt.compareSync(
			req.body.password,
			user.password
		);

		if (!passwordIsValid) {
			return res.status(401).send({
				accessToken: null,
				message: "Invalid Password!"
			});
		}

		var token = jwt.sign({ id: user.id }, config.secret, {
			expiresIn: config.jwtExpiration
		});

		let refreshToken = await RefreshToken.createToken(user);

		var authorities = [];
		user.getRoles().then(roles => {
			for (let i = 0; i < roles.length; i++) {
				authorities.push("ROLE_" + roles[i].name.toUpperCase());
			}

			// req.session.token = token;

			res.status(200).send({
				// id: user.id,
				// username: user.username,
				// email: user.email,
				roles: authorities,
				accessToken: token,
				refreshToken: refreshToken
			});
		});
	})
	.catch(err => {
		res.status(500).send({ message: err.message });
	});
};

exports.refreshToken = async (req, res) => {

	const { refreshToken: requestToken } = req.body;

	if (requestToken == null) {
		return res.status(403).send({ message: "Refresh Token is required!" });
	}

	try {
		let refreshToken = await RefreshToken.findOne({
			where: {
				token: requestToken
			}
		});

		if (!refreshToken) {
			res.status(403).send({ message: "Refresh Token is not in db!" });
			return;
		}

		if (RefreshToken.verifyExpiration(refreshToken)) {
			res.status(403).send({
				message: "Refresh Token has expired! Please log in again."
			});
			return;
		}

		const user = await refreshToken.getUser();
		let newAccessToken = jwt.sign({ id: user.id }, config.secret, {
			expiresIn: config.jwtExpiration
		})
		// req.session.token = newAccessToken;
		return res.status(200).send({
			msg: "The token has been refreshed",
			refreshToken: refreshToken.token,
			accessToken: newAccessToken
		});

	} catch (err) {
		res.status(500).send({ message: err.message });
	}

}

exports.signout = async (req, res) => {
	try {
		req.session = null;
		RefreshToken.revokeToken(req.body.refreshToken);
		return res.status(200).send({
			message: "You've been signed out!"
		});
	} catch (err) {
		this.next(err);
	}
};
  