import express from 'express';
import { loginControllers, registerControllers, setAvatarController, verifyEmailController, getUserData, forgotPasswordController, resetPasswordController } from '../controllers/userController.js';

const router = express.Router();

router.route("/register").post(registerControllers);

router.route("/login").post(loginControllers);

router.route("/setAvatar/:id").post(setAvatarController);

router.route('/verify-email').get(verifyEmailController); 

router.route('/user/:id').get(getUserData);

router.route('/forgot-password').post(forgotPasswordController);

router.route('/reset-password').post(resetPasswordController);

export default router;
