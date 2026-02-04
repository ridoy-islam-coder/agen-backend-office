/* eslint-disable @typescript-eslint/no-this-alias */
import bcrypt from 'bcrypt';
import { model, Schema } from 'mongoose';
import config from '../../config';

import { Types } from 'mongoose';
import { TUser, UserModel, UserRole } from './user.interface';

// Define the schema for Verification
const VerificationSchema = new Schema({
  otp: {
    type: Number, // Allows string or number
    // required: true,
  },
  expiresAt: {
    type: Date,
    // required: true,
  },

  status: {
    type: Boolean,
    required: true,
  },
});
const imageSchema = new Schema({
  id: {
    type: String, // Allows string or number
    required: true,
  },
  url: {
    type: String,
    required: true,
  },
});
// Define the schema for the User model
const UserSchema = new Schema<TUser, UserModel>(
  {
    email: {
      type: String,
      unique: true,
     required: function(this: TUser) {
     return this.accountType === 'custom';
  },
    },
    image: imageSchema,
    fullName: {
      type: String,
      required: true,
    },
    password: {
      type: String,
        required: function (this: TUser) {
        return this.accountType === 'custom';
      },
      default: '',
      select: false,
    },
    countryCode: {
      type: String,
        required: function (this: TUser) {
        return this.accountType === 'custom';
      }, 
      sparse: true, // 🔥 important
      default: '',
    },

    phoneNumber: {
      type: String,
      // required: true,
        required: function (this: TUser) {
         return this.accountType === 'custom';
      }, 
      sparse: true, // ⚡ social login এর জন্য
      unique: true,
      default: '',
    },
    needsPasswordChange: {
      type: Boolean,
      default: false,
    },
    passwordChangedAt: {
      type: Date,
    },
    accountType: {
      type: String,
      enum: ['custom', 'google', 'facebook', 'linkedin', 'apple'],
      default: 'custom',
    },
    // role: {
    //   type: String,
    //   enum: Object.values(UserRole),
    //   required: true,
    // },
    role: {
      type: String,
      enum: Object.values(UserRole),
      required: true,
      default: UserRole.customer, // ✅ Fix: Add default
    },
    gender: {
      type: String,
      enum: ['Male', 'Female'],
      required: function (this: TUser) {
        return this.accountType === 'custom';
      }, 
    },
    subscription: {
      plan: {
        type: Schema.Types.ObjectId,
        ref: 'Subscription',
      },
      startsAt: Date,
      expiresAt: Date,
      status: {
        type: String,
        enum: ['active', 'expired', 'cancelled'],
        default: 'active',
      },
    },

    isActive: {
      type: Boolean,
      default: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isDeleted: {
      type: Boolean,
      default: false,
    },
    verification: {
      type: VerificationSchema,
      required: false,
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
  },
);

// Pre-save hook to hash password if it is modified or new
// UserSchema.pre('save', async function (next) {
//   const user = this;
//   user.password = await bcrypt.hash(
//     user.password as string,
//     Number(config.bcrypt_salt_rounds),
//   );
//   next();
// });


//👉 Password change না হলে hash করবে না

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(
    this.password as string,
    Number(config.bcrypt_salt_rounds),
  );
  next();
});



// set '' after saving password
UserSchema.post('save', function (doc, next) {
  doc.password = '';
  next();
});

// Check if a user exists by email
UserSchema.statics.isUserExist = async function (
  email: string,
): Promise<TUser | null> {
  return this.findOne({ email }).select('+password');
};

// Check if a user exists by phone number
UserSchema.statics.isUserExistByNumber = async function (
  countryCode: string,
  phoneNumber: string,
) {
  return this.findOne({ countryCode, phoneNumber }).select('+password');
};

// Check if a user exists by ID
// UserSchema.statics.IsUserExistbyId = async function (
//   id: string,
// ): Promise<TUser | null> {
//   return this.findById(id);
// };

// UserSchema.statics.IsUserExistbyId = async function (
//   id: string,
// ): Promise<Pick<TUser, '_id' | 'email' | 'role' | 'password'> | null> {
//   return this.findById(id).select('+password');
// };

UserSchema.statics.IsUserExistbyId = async function (
  id: string,
): Promise<Pick<TUser, '_id' | 'email' | 'role' | 'password'> | null> {
  return this.findOne({
    _id: new Types.ObjectId(id),
    isDeleted: { $ne: true },
  }).select('+password');
};

// Compare plain text password with hashed password
UserSchema.statics.isPasswordMatched = async function (
  plainTextPassword: string,
  hashedPassword: string,
): Promise<boolean> {
  return bcrypt.compare(plainTextPassword, hashedPassword);
};

// filter out deleted documents
UserSchema.pre('find', function (next) {
  this.find({ isDeleted: { $ne: true } });
  next();
});

UserSchema.pre('findOne', function (next) {
  this.find({ isDeleted: { $ne: true } });
  next();
});

UserSchema.pre('aggregate', function (next) {
  this.pipeline().unshift({ $match: { isDeleted: { $ne: true } } });
  next();
});
// Create and export the User model
const User = model<TUser, UserModel>('User', UserSchema);

export default User;
