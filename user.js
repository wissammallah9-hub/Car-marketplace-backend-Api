const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const userSchema = new Schema ({
    name:{
        type:String,
        required:true,
        trim:true
    },
    email:{
        type:String,
        trim:true,
        required:true,
        unique:true,
        lowercase:true,
    },
    password:{
        type:String,
        required:true,
        minlength:[6,"too short"]
    },
    role:{
        type:String,
        enum:["user","admin"],
        default:"user"
    },
favourites:[{
    type:mongoose.Schema.Types.ObjectId,
    ref:"usercar"
}],
tokenversion:{
    type:Number,
    default:0
}
})
const user = mongoose.model("user",userSchema)
module.exports=user;