import User from "../models/UserSchema.js";
import bcrypt from "bcrypt";
import nodemailer from 'nodemailer';
import crypto from 'crypto';

// Define email sending function
const sendEmail = async (email, subject, html) => {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: subject,
        html: html,
    };

    return transporter.sendMail(mailOptions);
};

const sendVerificationEmail = async (email, token) => {
    const subject = 'Account Verification';
    const html = `<p>Please verify your email by clicking on the following link: <a href="${process.env.BASE_URL}/verify-email?token=${token}">Verify Email</a></p>`;
    return sendEmail(email, subject, html);
};

const sendPasswordResetEmail = async (email, token) => {
    const subject = 'Password Reset';
    const html = `<p>You requested a password reset. Click the link below to set a new password:</p><p><a href="${process.env.BASE_URL}/reset-password?token=${token}">Reset Password</a></p>`;
    return sendEmail(email, subject, html);
};


export const registerControllers = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please enter all fields",
            });
        }

        // Check for valid email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Invalid email format",
            });
        }

        // Case-insensitive email check
        let user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });

        if (user) {
            return res.status(409).json({
                success: false,
                message: "Email already exists",
            });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationTokenExpires = Date.now() + 3600000; // 1 hour

        let newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            verificationToken,
            verificationTokenExpires,
        });

        // Send verification email
        try {
            await sendVerificationEmail(email, verificationToken);
        } catch (emailError) {
            return res.status(500).json({
                success: false,
                message: "Failed to send verification email. Please try again later.",
            });
        }

        // Remove password from the user object before sending response
        const userResponse = { ...newUser._doc };
        delete userResponse.password;

        return res.status(201).json({
            success: true,
            message: "User created successfully. Please check your email to verify your account.",
            user: userResponse,
        });
    } catch (err) {
        console.error("Registration error:", err);
        return res.status(500).json({
            success: false,
            message: "An internal server error occurred",
        });
    }
};

export const verifyEmailController = async (req, res, next) => {
    try {
      const { token } = req.query; // Get the token from the query parameters
      console.log("Token received in controller:", token); // Debugging
  
      if (!token) {
        return res.status(400).json({
          success: false,
          message: 'No token provided.',
        });
      }
  
      // Check the validity of the token
      const user = await User.findOne({
        verificationToken: token,
        verificationTokenExpires: { $gt: Date.now() }
      });
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired token.',
        });
      }
  
      user.isVerified = true;
      user.verificationToken = undefined;
      user.verificationTokenExpires = undefined;
      await user.save();
  
      return res.status(200).json({
        success: true,
        message: 'Email verified successfully.',
      });
    } catch (err) {
      console.error("Verification error:", err);
      return res.status(500).json({
        success: false,
        message: "An internal server error occurred",
      });
    }
  };
   
  export const loginControllers = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please enter all fields",
            });
        }

        // Check for valid email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Invalid email format",
            });
        }

        // Find the user (case-insensitive search)
        const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User not found",
            });
        }

        // Check password match
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Incorrect email or password",
            });
        }

        // Check if user is verified
        if (!user.isVerified) {
            const verificationToken = crypto.randomBytes(32).toString('hex');
            user.verificationToken = verificationToken;
            user.verificationTokenExpires = Date.now() + 3600000; // 1 hour
            await user.save();

            // Send verification email
            try {
                await sendVerificationEmail(email, verificationToken);
            } catch (emailError) {
                return res.status(500).json({
                    success: false,
                    message: "Failed to send verification email. Please try again later.",
                });
            }

            return res.status(401).json({
                success: false,
                message: "Email not verified. A new verification email has been sent.",
            });
        }

        // Remove password before sending response
        const userResponse = { ...user._doc };
        delete userResponse.password;

        return res.status(200).json({
            success: true,
            message: `Welcome back, ${user.name}`,
            user: userResponse,
        });
    } catch (err) {
        console.error("Login error:", err); // Log error for debugging
        return res.status(500).json({
            success: false,
            message: "An internal server error occurred",
        });
    }
};

export const setAvatarController = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const imageData = req.body.image;

        const userData = await User.findByIdAndUpdate(userId, {
            isAvatarImageSet: true,
            avatarImage: imageData,
        }, { new: true });

        return res.status(200).json({
            isSet: userData.isAvatarImageSet,
            image: userData.avatarImage,
        });
    } catch (err) {
        next(err);
    }
}

export const allUsers = async (req, res, next) => {
    try {
        const user = await User.find({ _id: { $ne: req.params.id } }).select([
            "email",
            "username",
            "avatarImage",
            "_id",
        ]);

        return res.json(user);
    } catch (err) {
        next(err);
    }
}

export const getUserData = async (req, res, next) => {
    try {
        const userId = req.params.id;
        
        // Find user by ID and select specific fields
        const user = await User.findById(userId)
            .select('name email avatarImage isVerified'); // Include the fields you need
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        return res.status(200).json({
            success: true,
            user,
        });
    } catch (err) {
        console.error("Fetch user data error:", err);
        return res.status(500).json({
            success: false,
            message: "An internal server error occurred",
        });
    }
};

// Forgot password controller
export const forgotPasswordController = async (req, res, next) => {
    try {
      const { email } = req.body;
  
      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Please enter your email",
        });
      }
  
      // Find the user (case-insensitive search)
      const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });
  
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Email not found",
        });
      }
  
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();
  
      // Send password reset email
      try {
        await sendPasswordResetEmail(email, resetToken);
      } catch (emailError) {
        return res.status(500).json({
          success: false,
          message: "Failed to send password reset email. Please try again later.",
        });
      }
  
      return res.status(200).json({
        success: true,
        message: "Password reset email sent successfully.",
      });
    } catch (err) {
      console.error("Forgot password error:", err);
      return res.status(500).json({
        success: false,
        message: "An internal server error occurred",
      });
    }
  };
  

export const resetPasswordController = async (req, res, next) => {
    try {
      const { token, newPassword } = req.body;
      console.log('Received Token:', token); // Debugging line
      console.log('Received New Password:', newPassword); // Debugging line
  
      if (!token || !newPassword) {
        return res.status(400).json({
          success: false,
          message: "Invalid request",
        });
      }
  
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }
      });
  
      if (!user) {
        console.log('Token not found or expired'); // Debugging line
        return res.status(400).json({
          success: false,
          message: "Invalid or expired token",
        });
      }
  
      // Hash the new password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
  
      return res.status(200).json({
        success: true,
        message: "Password reset successfully",
      });
    } catch (err) {
      console.error("Reset password error:", err);
      return res.status(500).json({
        success: false,
        message: "An internal server error occurred",
      });
    }
  };
  
  

