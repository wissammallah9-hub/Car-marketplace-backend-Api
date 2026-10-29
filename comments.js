const mongoose = require("mongoose")
const commentSchema = new mongoose.Schema({
    user:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"user"
    },
    car:{
        
     type:mongoose.Schema.Types.ObjectId,
        
    ref:"usercar"
        
    },
    text:{
        type:String,
        required:true
    }
},
{timestamps:true});
const comments = mongoose.model("comments",commentSchema)
module.exports=comments;