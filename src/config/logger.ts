import pino from "pino";
import { config } from "./env";

export const logger = pino({
  level: config.nodeEnv === "development" ? "debug" : "info",
  base: undefined,
  timestamp: pino.stdTimeFunctions.isoTime
});
