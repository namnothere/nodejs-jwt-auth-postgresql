module.exports = (sequelize, Sequelize) => {
    const Role = sequelize.define("Role", {
        id: {
            type: Sequelize.INTEGER,
            primaryKey: true,
        },
        name: {
            type: Sequelize.STRING,
        }
    });
    return Role;
}