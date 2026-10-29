
const dns = require("dns");
dns.setServers(["8.8.8.8", "1.1.1.1"]);
const comments = require("./comments.js")
const user = require("./user.js");
require("dotenv").config();
const usercar = require("./carsschema.js");
const bcrypt = require("bcrypt");
const express = require("express");
const revokedtoken = require("./revokedtoken.js");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "20kb" }));

if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
    throw new Error("MONGO_URI and JWT_SECRET are required in .env");
}

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch((error) => console.error("MongoDB connection error:", error.message));

const Tokenbouncer = async (req, res, next) => {
    try {
        const authheader = req.headers.authorization;
        
        if (!authheader || !authheader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Token is missing" });
        }
        
        const token = authheader.split(" ")[1];
        
        if (!token) return res.status(401).json({ message: "Token is missing" });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
        
        if (!decoded.userId || !mongoose.isValidObjectId(decoded.userId)) {
            return res.status(401).json({ message: "Invalid token" });
        }
        
        const revoked = await revokedtoken.findOne({ token });
        
        if (revoked) return res.status(401).json({ message: "Token has been revoked" });
        
        const existinguser = await user.findById(decoded.userId);
        
        if (!existinguser) return res.status(401).json({ message: "Account no longer exists" });


        if (decoded.tokenVersion !== existinguser.tokenVersion) {
    return res.status(401).json({
        message: "Token expired due to password change"
    });
}
        req.user = decoded;
        req.token = token;
        next();
    } catch (error) {
        if (["JsonWebTokenError", "TokenExpiredError", "NotBeforeError"].includes(error.name)) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }
        
        console.error(error);
        return res.status(500).json({ message: "Authentication server error" });
    }
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// register endpoint
app.post("/api/account/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        if (typeof name !== "string" || !name.trim() || typeof email !== "string" || !email.trim() || typeof password !== "string") {
            return res.status(400).json({ message: "Name, email and password required" });
        }
        
        if (password.length < 6 || password.length > 72) {
            return res.status(400).json({ message: "Password must be 6 to 72 characters" });
        }
        
        const cleanemail = email.trim().toLowerCase();
        
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanemail)) {
            return res.status(400).json({ message: "Invalid email" });
        }
        
        const existinguser = await user.findOne({ email: cleanemail });
        
        if (existinguser) return res.status(409).json({ message: "Email already exists" });
        
        const hashedpass = await bcrypt.hash(password, 12);
        const newuser = await user.create({ name: name.trim(), email: cleanemail, password: hashedpass });
        
        return res.status(201).json({ message: "User created", user: { id: newuser.id, name: newuser.name, email: newuser.email } });
    } catch (error) {
        if (error.code === 11000) return res.status(409).json({ message: "Email already exists" });
        
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// login endpoint
app.post("/api/account/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (typeof email !== "string" || !email.trim() || typeof password !== "string" || !password) {
            return res.status(400).json({ message: "Email or password required" });
        }
        
        const existinguser = await user.findOne({ email: email.trim().toLowerCase() });
        
        if (!existinguser) return res.status(401).json({ message: "Invalid email or password" });
        
        const ispassmatched = await bcrypt.compare(password, existinguser.password);
        
        if (!ispassmatched) return res.status(401).json({ message: "Invalid email or password" });
        
        const token = jwt.sign({ userId: existinguser._id,
            tokenversion:existinguser.tokenversion
         }, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: "2m" });
        
        return res.status(200).json({ message: "User logged in successfully", user: { id: existinguser.id, name: existinguser.name, email: existinguser.email, token } });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// get account endpoint
app.get("/api/account/me", Tokenbouncer, async (req, res) => {
    try {
        const existingUser = await user.findById(req.user.userId).select("-password");
        
        if (!existingUser) return res.status(404).json({ message: "User not found" });
        
        return res.status(200).json({ message: "Here is your account info", user: { id: existingUser.id, name: existingUser.name, email: existingUser.email } });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// editing account endpoint (changes password only,)
app.patch("/api/account/edit", Tokenbouncer, async (req, res) => {
    try {
        const { password, newpassword } = req.body;
        
        if (typeof password !== "string" || !password || typeof newpassword !== "string" || !newpassword) {
            return res.status(400).json({ message: "Current and new password required" });
        }
        
        if (newpassword.length < 6 || newpassword.length > 72) {
            return res.status(400).json({ message: "New password must be 6 to 72 characters" });
        }
        
        const existinguser = await user.findById(req.user.userId);
        
        if (!existinguser) return res.status(404).json({ message: "User not found" });
        
        const ispassmatched = await bcrypt.compare(password, existinguser.password);
        
        if (!ispassmatched) return res.status(401).json({ message: "Password incorrect" });
        
        const hashedpass = await bcrypt.hash(newpassword, 12);
        existinguser.password = hashedpass;
        existinguser.tokenversion+=1;
        await existinguser.save();
        
        return res.status(200).json({ message: "Password updated successfully", user: { id: existinguser.id, name: existinguser.name, email: existinguser.email } });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// delete account endpoint
app.delete("/api/account/delete", Tokenbouncer, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (typeof password !== "string" || !password) return res.status(400).json({ message: "Password required" });
        
        const existinguser = await user.findById(req.user.userId);
        
        if (!existinguser) return res.status(404).json({ message: "User not found" });
        
        const ispasswordmatched = await bcrypt.compare(password, existinguser.password);
        
        if (!ispasswordmatched) return res.status(401).json({ message: "Invalid password" });
        
        await usercar.deleteMany({ owner: req.user.userId });
        await comments.deleteMany({ user: req.user.userId });
        await user.findByIdAndDelete(req.user.userId);
        
        return res.status(200).json({ message: "Account deleted" });
        
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// logout endpoint
app.post("/api/account/logout", Tokenbouncer, async (req, res) => {
    try {
        await revokedtoken.create({ token: req.token, expiresAt: new Date(req.user.exp * 1000) });
        
        return res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        return res.status(500).json({ message: "Logout failed" });
    }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// add car endpoint
app.post("/api/cars/add", Tokenbouncer, async (req, res) => {
    try {
        const { brand, model, price, year, fueltype, km } = req.body;
    
        
        if (typeof brand !== "string" || !brand.trim() || typeof model !== "string" || !model.trim() || typeof fueltype !== "string" || !fueltype.trim() || typeof price !== "number" || !Number.isFinite(price) || price <= 0 || typeof year !== "number" || !Number.isInteger(year) || year < 1886 || year > new Date().getFullYear() + 1 || typeof km !== "number" || !Number.isFinite(km) || km < 0) {
            return res.status(400).json({ message: "Invalid or missing car fields" });
        }
        
        const carcreat = await usercar.create({ brand: brand.trim(), model: model.trim(), price, year, fueltype: fueltype.trim(), km, owner: req.user.userId });
        
        return res.status(201).json({ message: "Car added successfully", car: { id: carcreat._id, brand: carcreat.brand, model: carcreat.model, price: carcreat.price } });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

//get all cars endpoint
app.get("/api/cars/getall", Tokenbouncer, async (req, res) => {
    try {
        const allcars = await usercar.find();
        
        return res.status(200).json({ message: "Here you go", allcars });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

// get specific car endpoint
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/api/cars/specefic/:id", Tokenbouncer, async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid car ID" });
        
        const car = await usercar.findById(req.params.id);
        
        if (!car) return res.status(404).json({ message: "Car not found" });
        
        return res.status(200).json({ message: "Car found successfully", car });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// editing car endpoint (PATCH: only fields sent are updated)
app.patch("/api/cars/edit/:id", Tokenbouncer, async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid car ID" });
        
        const { newbrand, newmodel, newprice, newyear, newfueltype, newkm } = req.body;
        
        if (newbrand === undefined && newmodel === undefined && newprice === undefined && newyear === undefined && newfueltype === undefined && newkm === undefined) {
            return res.status(400).json({ message: "Send at least one field to update" });
        }
        
        const existingcar = await usercar.findById(req.params.id);
        
        if (!existingcar) return res.status(404).json({ message: "Car not found" });
        
        if (!existingcar.owner || existingcar.owner.toString() !== req.user.userId.toString()) {
            return res.status(403).json({ message: "You are not the owner" });
        }
        
        if (newbrand !== undefined) {
            if (typeof newbrand !== "string" || !newbrand.trim()) return res.status(400).json({ message: "Invalid brand" });
            existingcar.brand = newbrand.trim();
        }
        
        if (newmodel !== undefined) {
            if (typeof newmodel !== "string" || !newmodel.trim()) return res.status(400).json({ message: "Invalid model" });
            existingcar.model = newmodel.trim();
        }
        
        if (newprice !== undefined) {
            if (typeof newprice !== "number" || !Number.isFinite(newprice) || newprice <= 0) return res.status(400).json({ message: "Invalid price" });
            existingcar.price = newprice;
        }
        
        if (newyear !== undefined) {
            if (typeof newyear !== "number" || !Number.isInteger(newyear) || newyear < 1886 || newyear > new Date().getFullYear() + 1) return res.status(400).json({ message: "Invalid year" });
            existingcar.year = newyear;
        }
        
        if (newfueltype !== undefined) {
            if (typeof newfueltype !== "string" || !newfueltype.trim()) return res.status(400).json({ message: "Invalid fuel type" });
            existingcar.fueltype = newfueltype.trim();
        }
        
        if (newkm !== undefined) {
            if (typeof newkm !== "number" || !Number.isFinite(newkm) || newkm < 0) return res.status(400).json({ message: "Invalid km" });
            existingcar.km = newkm;
        }
        
        await existingcar.save();
        
        return res.status(200).json({ message: "Car updated successfully", updatedcar: existingcar });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//deleting car endpoint
app.delete("/api/cars/delete/:id", Tokenbouncer, async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid car ID" });
        
        const { password } = req.body;
        
        if (typeof password !== "string" || !password) return res.status(400).json({ message: "Password required" });
        
        const existinguser = await user.findById(req.user.userId);
        
        if (!existinguser) return res.status(404).json({ message: "User not found" });
        
        const ispasswordmatched = await bcrypt.compare(password, existinguser.password);
        
        if (!ispasswordmatched) return res.status(401).json({ message: "Invalid password" });
        
        const existingcar = await usercar.findById(req.params.id);
        
        if (!existingcar) return res.status(404).json({ message: "Car not found" });
        
        if (!existingcar.owner || existingcar.owner.toString() !== req.user.userId.toString()) {
            return res.status(403).json({ message: "You are not the owner" });
        }
        
        await usercar.findByIdAndDelete(req.params.id);
        
        return res.status(200).json({ message: "Car deleted successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Server error" });
    }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//get filtering car price endpoint
app.get("/api/cars/price",Tokenbouncer,async (req,res)=>{
    try{
const {minprice,maxprice} = req.query;
if(minprice === undefined || maxprice === undefined){
    return res.status(400).json({
        message:"price filter field required!"
    })
};
 
if(!Number.isFinite(Number(minprice)) || !Number.isFinite(Number(maxprice)) || String(minprice).trim() === "" || String(maxprice).trim() === "" || Number(minprice) < 0 || Number(maxprice) < 0 || Array.isArray(minprice) || Array.isArray(maxprice)){
    return res.status(400).json({
        message:"Invalid price range"
    })
};

if(Number(minprice)>Number(maxprice)){
    return res.status(400).json({
        message:"Invalid price range"
    })
};

const filter = await usercar.find({price:{
    $gte:Number(minprice),
    $lte:Number(maxprice)
}});
if(filter.length===0){
 return   res.status(200).json({
        message:"no cars found",
        count:0,
        filter:[]
    }
    )
}


res.status(200).json({
    message:"this is avalibale cars in range",
    count:filter.length,
    filter
})

    }catch(error){
      console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//get filtering car endpoint
app.get("/api/cars",Tokenbouncer,async (req,res)=>{
    try{
const {brand,model,year,fueltype,km} = req.query;
if(Object.keys(req.query).length ===0 ){
    return res.status(400).json({
        message:"filter fields required!"
    })
};
const allowedFields = ["brand", "model", "year", "fueltype", "km"];
if(Object.keys(req.query).some(key => !allowedFields.includes(key)) || Object.values(req.query).some(value => typeof value !== "string" || !value.trim())){
    return res.status(400).json({ message:"Invalid filter fields" });
};
if((year !== undefined && (!Number.isInteger(Number(year)) || Number(year) < 1886 || Number(year) > new Date().getFullYear() + 1)) || (km !== undefined && (!Number.isFinite(Number(km)) || Number(km) < 0))){
    return res.status(400).json({ message:"Invalid year or km" });
};
const filter = await usercar.find({
    ...(brand !== undefined ? {brand} : {}),
    ...(model !== undefined ? {model} : {}),
    ...(year !== undefined ? {year:Number(year)} : {}),
    ...(fueltype !== undefined ? {fueltype} : {}),
    ...(km !== undefined ? {km:Number(km)} : {})
});
res.status(200).json({
    message:"this is avalibale brands",
    filter
})

    }catch(error){
      console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
});
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//sort on price(high to low) endpoint
app.get("/api/cars/sort/highlow",Tokenbouncer,async(req,res)=>{
    try{
const cars = await usercar.find({});
cars.sort((a,b)=>b.price - a.price);
return res.status(200).json({
cars
})
    }catch(error){

        console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
})
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//low to high sort on price
app.get("/api/cars/sort/lowhigh",Tokenbouncer,async(req,res)=>{
    try{
const cars = await usercar.find({});
cars.sort((a,b)=>a.price - b.price);
return res.status(200).json({
cars
})
    }catch(error){
        
        console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//add car to favourite endpoint
app.post("/api/cars/:id/favourites", Tokenbouncer, async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.isValidObjectId(id)) {
            return res.status(400).json({ message: "invalid car id" });
        }

        const existingcar = await usercar.findById(id);
        console.log("user grabbing works")
        if (!existingcar) {
            return res.status(404).json({ message: "car not found" });
        }

        const currentUser = await user.findById(req.user.userId);
        if (!currentUser) {
            return res.status(404).json({ message: "user not found" });
        }

       
     const updateduser=   await user.findByIdAndUpdate(
            currentUser._id,
            { $addToSet: { favourites: existingcar.id} },
            { new: true, runValidators: true }
        );

      

        return res.status(200).json({
            message: "added to favourite successfully",
            favourites: updateduser.favourites
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//delete from favourite
app.delete("/api/cars/:id/favourites/delete", Tokenbouncer, async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.isValidObjectId(id)) {
            return res.status(400).json({ message: "invalid car id" });
        }

        const existingcar = await usercar.findById(id);
        if (!existingcar) {
            return res.status(404).json({ message: "car not found" });
        }

        const currentUser = await user.findById(req.user.userId);
        if (!currentUser) {
            return res.status(404).json({ message: "user not found" });
        }

       
     const updateduser=   await user.findByIdAndUpdate(
            currentUser._id,
            { $pull: { favourites: existingcar.id} },
            { new: true }
        );

        return res.status(200).json({
            message: "removed from favourite successfully",
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
});
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//get all user favourites endpoint

app.get("/api/me/favourites",Tokenbouncer,async (req,res)=>{
    try{
const existingfavourites = await user.findById(req.user.userId)
if(!existingfavourites){
    return res.status(404).json({ message:"user not found" })
};
if(!existingfavourites.favourites || existingfavourites.favourites.length ===0){
    return res.status(200).json({
        message:"there is no favourites",
        favourites:[]
    })
};
res.status(200).json({
    message:"here is your favourites",
   favourites:existingfavourites.favourites
})

    }catch(error){
       console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
}


)
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//add comment endpoint
app.post("/api/cars/comments/:id", Tokenbouncer, async(req,res)=>{
    try {
        const {comment} = req.body;

        if(typeof comment !== "string" || !comment.trim()){
            return res.status(400).json({
                message:"comment field empty!"
            });
        }

        if(!mongoose.isValidObjectId(req.params.id)){
            return res.status(400).json({
                message:"Invalid car id"
            });
        }

        const existingcar = await usercar.findById(req.params.id);


        if(!existingcar){
            return res.status(404).json({
                message:"car not found"
            });
        }
console.log("comments:", comments);
console.log("Type:", typeof comments);
console.log("Create:", typeof comments.create);
        const newcomment = await comments.create({
            user:req.user.userId,
            car:existingcar._id,
            text:comment
        });

        return res.status(201).json({
            message:"comment added",
            comment:newcomment
        });

    }catch(error){
        return res.status(500).json({
            message:"Server error"
        });
    }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//get comments endpoint
app.get("/api/cars/comments/:id",async (req,res)=>{
    try{
const id=req.params.id;
if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid car id" });
if(!id){
 return   res.status(400).json({
        message:"car id empty"
    })
};
const existingcomment = await comments.find({car:id});
if(existingcomment.length === 0){
    return res.status(200).json({
        message:"no comments found",
        existingcomment:[]
    })
};
res.status(200).json({
    existingcomment
})
    }catch(error){
   return res.status(500).json({
            message: "Server error"
        });
    }
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//delete endpoint for comments
app.delete("/api/comments/delete/:id", Tokenbouncer, async (req, res) => {
    try {
        const id = req.params.id;

        if (!id || !mongoose.isValidObjectId(id)) {
            return res.status(400).json({
                message: "Invalid or missing comment id"
            });
        }

       
        const delcomment = await comments.findOneAndDelete({
            _id: id,
            user: req.user.userId
        });

        
        if (!delcomment) {
            return res.status(404).json({
                message: "Comment not found or you do not have permission to delete it"
            });
        }

        return res.status(200).json({
            message: "Comment deleted successfully"
        });

    } catch (error) {
        return res.status(500).json({
            message: "Server error"
        });
    }
});

const port = 3000;
app.listen(port, () => console.log("Server listening on port 3000"));
