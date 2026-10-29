const mongoose = require("mongoose");

const revokedTokenSchema = new mongoose.Schema({
    token: {
        type: String,     
        required: true,
        unique: true,
    },
    expiresAt: {
        type: Date,      
        required: true,
        expires: 0        
    }
});

const revokedToken = mongoose.model("revokedToken", revokedTokenSchema);
module.exports = revokedToken;


/*{
    "name":"jafar",
    "email":"jafar@123",
    "password":"jafar12345"*/