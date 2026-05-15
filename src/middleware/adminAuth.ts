import type { Request, Response, NextFunction } from "express";
import { logger } from "../config/logger";

export const createAdminAuth = (apiKey: string) => {
  const isEnabled = apiKey.trim().length > 0;

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!isEnabled) {
      next();
      return;
    }

    const provided =
      req.headers["x-api-key"] as string | undefined ??
      req.query["api_key"] as string | undefined;

    if (!provided || provided !== apiKey) {
      logger.warn(
        { ip: req.ip, path: req.path },
        "Unauthorized admin access attempt"
      );
      res.status(401).json({ error: "Unauthorized. Provide a valid X-Api-Key header." });
      return;
    }

    next();
  };
};
