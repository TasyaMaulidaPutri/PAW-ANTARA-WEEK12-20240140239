const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

/**
 * Model Comment — dipakai buat fitur "Komentar Produk" (Bagian 2 tugas).
 * Sengaja dibikin baru (bukan modif Product) biar gak nyampur sama data
 * demo Bagian 1.
 */
const Comment = sequelize.define(
  'Comment',
  {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false },
    message: { type: DataTypes.TEXT, allowNull: false },
  },
  { tableName: 'comments', timestamps: true }
);

module.exports = Comment;
