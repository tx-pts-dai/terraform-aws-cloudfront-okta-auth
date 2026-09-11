import config from "./config.mjs";
import { createHandler } from "./auth.mjs";

export const handler = createHandler(config);
