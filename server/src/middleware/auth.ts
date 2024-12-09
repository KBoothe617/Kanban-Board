import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers['authorization'];

  if (authHeader) {
    const token = authHeader.split(' ')[1];
    const secretKey: string | undefined = process.env.JWT_SERCRET_KEY;
    if (!secretKey) {
      res.sendStatus(500); // Internal Server Error if secret key is not defined
      return;
    }
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        res.sendStatus(403);
        return;
      }
      req.user = user as JwtPayload; // Add user data to the request object
      next();
    });
  } else {
    res.sendStatus(401);
  }
};
