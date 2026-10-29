const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const carsSchema = new Schema({
    brand: {
        type: String,
        required: true, 
        trim: true,
    },
    model: {
        type: String,
        required: true,
    },
    year: {
        type: Number,
        required: true, 
    },
    price: {
        type: Number,
        required: true,
    },
    fueltype: {
        type: String,
        required: true, 
      enum:["gasoline","diesle"]
    },
    km: {
        type: Number,
        required: true,
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user",
    },

})

const usercar = mongoose.model("usercar", carsSchema);
module.exports = usercar;