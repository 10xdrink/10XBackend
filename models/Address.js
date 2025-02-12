// models/Address.js
const mongoose = require('mongoose');

const AddressSchema = new mongoose.Schema(
  {
    street: {
      type: String,
      required: [true, 'Please add a street'],
      trim: true,
    },
    city: {
      type: String,
      required: [true, 'Please add a city'],
      trim: true,
    },
    state: {
      type: String,
      required: [true, 'Please add a state'],
      trim: true,
    },
    zip: {
      type: String,
      required: [true, 'Please add a zip code'],
      trim: true,
    },
    country: {
      type: String,
      required: [true, 'Please add a country'],
      trim: true,
    },
  },
  { _id: true } // Ensures each address has a unique _id
);

module.exports = AddressSchema;
