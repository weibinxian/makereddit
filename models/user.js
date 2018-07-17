const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt')

const UserSchema = new Schema({

password: { type: String, required: true },
username: 
{
  type: String,
  lowercase: true,
  required: true,
  validate: {
      isAsync: true,
      validator: function(value, isValid) {
          const self = this;
          return self.constructor.findOne({ username : value })
          .exec(function(err, user){
              if(err){
                  throw err;
              }
              else if(user) {
                  if(self.id === user.id) {  // if finding and saving then it's valid even for existing email
                      return isValid(true);
                  }
                  return isValid(false);  
              }
              else{
                  return isValid(true);
              }

          })
      },
      message:  'This username is already taken!'
  },
}


});

// pre method takes a call back
UserSchema.pre('save',function(next){
let user= this;


// call the hash function and crypt the password
bcrypt.hash(user.password,10 , function (err, hash){
  if(err) return next(err);

  user.password=hash;
next();

})

});


//User authenticate
//authenticate() when users send us their password,
//which happens when they submit the login form
UserSchema.statics.authenticate = function(username, password, next) {
  User.findOne({ username: username })
    .exec(function (err, user){
      if(err){
        return next(err)
      }
    else if(!user){
      var err= new Error('User not found.');
      err.status = 401;
      return next(err);
    }

    bcrypt.compare(password, user.password, function (err, result) {
      if(result === true){
        return next(null, user);
      }
    else{
      next();
    }
  });
});


}
const User = mongoose.model('User', UserSchema);

module.exports = User;
