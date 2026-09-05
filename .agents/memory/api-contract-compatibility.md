---
name: API contract compatibility
description: Compatibility note for the generated Zod schemas in this workspace.
---

OpenAPI `integer` fields currently generate `zod.int()` in the checked-in client/server schemas, while the workspace resolves Zod 3 at typecheck time. Use numeric fields in the contract when generated validation must compile.

**Why:** The mismatch only appears after Orval generation and blocks the shared library typecheck, even though code generation itself succeeds.

**How to apply:** When adding numeric API fields, confirm the generated `lib/api-zod/src/generated/api.ts` remains compatible before building routes or the frontend.