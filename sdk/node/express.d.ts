// Types for the 'wedge-rp/express' subpath. The Router type is left loose so
// wedge-rp needs no dependency on @types/express (Express 4 and 5 both work).

import type { WedgeRP } from './index.js';

export interface WedgeRouterOptions {
  login: (username: string, req: unknown, res: unknown) => void | Promise<void>;
  redirectTo?: string | ((username: string) => string);
  failureRedirect?: string;
}

export declare function wedgeRouter(rp: WedgeRP, options: WedgeRouterOptions): unknown;
