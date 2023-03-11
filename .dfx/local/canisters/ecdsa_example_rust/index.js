import { Actor, HttpAgent } from "@dfinity/agent";

// Imports and re-exports candid interface
import { idlFactory } from './ecdsa_example_rust.did.js';
export { idlFactory } from './ecdsa_example_rust.did.js';
// CANISTER_ID is replaced by webpack based on node environment
export const canisterId = process.env.ECDSA_EXAMPLE_RUST_CANISTER_ID;

/**
 * @deprecated since dfx 0.11.1
 * Do not import from `.dfx`, instead switch to using `dfx generate` to generate your JS interface.
 * @param {string | import("@dfinity/principal").Principal} canisterId Canister ID of Agent
 * @param {{agentOptions?: import("@dfinity/agent").HttpAgentOptions; actorOptions?: import("@dfinity/agent").ActorConfig} | { agent?: import("@dfinity/agent").Agent; actorOptions?: import("@dfinity/agent").ActorConfig }} [options]
 * @return {import("@dfinity/agent").ActorSubclass<import("./ecdsa_example_rust.did.js")._SERVICE>}
 */
export const createActor = (canisterId, options = {}) => {
  console.warn(`Deprecation warning: you are currently importing code from .dfx. Going forward, refactor to use the dfx generate command for JavaScript bindings.

See https://internetcomputer.org/docs/current/developer-docs/updates/release-notes/ for migration instructions`);
  const agent = options.agent || new HttpAgent({ ...options.agentOptions });
  
  // Fetch root key for certificate validation during development
  if (process.env.DFX_NETWORK !== "ic") {
    agent.fetchRootKey().catch(err => {
      console.warn("Unable to fetch root key. Check to ensure that your local replica is running");
      console.error(err);
    });
  }

  // Creates an actor with using the candid interface and the HttpAgent
  return Actor.createActor(idlFactory, {
    agent,
    canisterId,
    ...(options ? options.actorOptions : {}),
  });
};
  
/**
 * A ready-to-use agent for the ecdsa_example_rust canister
 * @type {import("@dfinity/agent").ActorSubclass<import("./ecdsa_example_rust.did.js")._SERVICE>}
 */
export const ecdsa_example_rust = createActor(canisterId);